from math import floor
from peewee import Model
from peewee import Proxy
from peewee import Float
from peewee import Integer
from peewee import PrimaryKeyField
from peewee import TextField

from datetime import datetime
from playhouse.postgres_ext import ArrayField
from playhouse.postgres_ext import JSONField

vulner_db_proxy = Proxy()

def unify_dt(dt):
    return datetime.strptime(dt.strftime('%Y-%m-%d %H:%M:%S'), '%Y-%m-%d %H:%M:%S')

def dt2str(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S')

def str2dt(dts):
    return datetime.strptime(dts, '%Y-%m-%d %H:%M:%S')

def onlydigits(s):
    return re.sub("\D\.\?", "", s)

def filter_version(version):
    if version == "" or version == "*" or version == "-":
        version = "?"
    return version

default_vulner_id_undefined = "SPVID:undefined:"
default_vulner_id_start = "SPVID:"
default_vulner_id_delimeter = ":"

def make_vulner_id():
    pass

class VULNERABILITIES(Model):

    class Meta:
        database = vulner_db_proxy
        ordering = ("componentversion_string", )
        table_name = "vulnerabilities"

    # - ID
    id = PrimaryKeyField(null=False)
    vulner_id = TextField(default=default_vulner_id_undefined)
    component = TextField(default="undefined")
    # - time
    published = TextField(default="undefined")
    modified = TextField(default="undefined")
    created = TextField(default="undefined")
    last_seen = TextField(default="undefined")
    cvss_time = TextField(default="undefined")
    # - scores
    cvss_score = Float(default=0.0)
    cvss_rank = Integer(default=0)
    cvss_vector = TextField(default="undefined")
    # - description
    title = TextField(default="undefined")
    description = TextField(default="undefined")
    details = TextField(default="undefined")
    recommendations = TextField(default="undefined")
    author = TextField(default="undefined")
    type = TextField(default="undefined")
    source = TextField(default="undefined")
    vulnerable_versions = TextField(default="undefined")
    patched_versions = TextField(default="undefined")
    access = JSONField(default=dict(vector="NETWORK", complexity="MEDIUM", authentication="NONE"))
    impact = JSONField(default=dict(confidentiality="PARTIAL", integrity="PARTIAL", availability="PARTIAL"))
    references = ArrayField(TextField, default=[])
    # - relation IDs
    ms_list = ArrayField(TextField, default=[])
    cve_list = ArrayField(TextField, default=[])
    cpe_list = ArrayField(TextField, default=[])
    cwe_list = ArrayField(TextField, default=[])
    cwe_id_list = ArrayField(TextField, default=[])
    npm_list = ArrayField(TextField, default=[])
    thn_list = ArrayField(TextField, default=[])
    bld_list = ArrayField(TextField, default=[])
    snyk_list = ArrayField(TextField, default=[])
    capec_list = ArrayField(TextField, default=[])
    osvdb_list = ArrayField(TextField, default=[])
    # special
    componentversions = ArrayField(TextField, default=[])
    componentversions_string = ArrayField(TextField, default=[])

    def save(self, **kwargs):
        with vulner_db_proxy.transaction():
            self.cvss_rank = floor(float(self.cvss_score))
            if isinstance(self.published, datetime):
                self.published = dt2str(self.published)
            if isinstance(self.modified, datetime):
                self.modified = dt2str(self, modified)
            if isinstance(self.last_seen, datetime):
                self.last_seen = dt2str(self.last_seen)
            if isinstance(self.created, datetime):
                self.created = dt2str(self.created)
            if isinstance(self.cvss_time, datetime):
                self.cvss_time = dt2str(self.cvss_time)
            self.cwe_id_list = [onlydigits(cwe) for cwe in self.cwe_list]
            self.componentversions_string =";".join(self.componentversions)


            # TODO: Check if self.id defined after Model.save or before Model.save

            if self.vulner_id == default_vulner_id_undefined:
                self.vulner_id = default_vulner_id_start + self.component + default_vulner_id_delimeter + self.id

            Model.save(self, **kwargs)

    @property
    def to_json(self):
        template = dict()
        template["__v"] = 0
        template["_id"] = self.id
        template["title"] = self.vulner_id
        template["component"] = self.component
        template["Created"] = str2dt(self.created)
        template["Published"] = str2dt(self.published)
        template["Modified"] = str2dt(self.modified)
        template["LastSeen"] = str2dt(self.lastseen)
        template["cvss_time"] = str2dt(self.cvss_time)
        template["cvss_score"] = self.vss_score
        template["cvss_rank"] = self.cvss_rank
        template["vector_string"] = self.cvss_vector
        template["description"] = self.description
        template["details"] = self.details
        template["recommendations"] = self.recommendations
        template["author"] = self.author
        template["type"] = self.type
        template["source"] = self.source
        template["vulnerable_versions"] = self.vulnerable_versions
        template["patched_versions"] = self.patched_versions
        template["access"] = self.access
        template["impact"] = self.impact
        template["cve_references"] = self.references
        template["ms_list"] = self.ms_list
        template["cve_list"] = self.cve_list
        template["cwe"] = self.cwe_list
        template["cwe_id"] = self.cwe_id_list
        template["capec"] = self.capec_list
        template["vulnerable_configurations"] = []
        template["vulnerable_configuration"] = self.cpe_list
        template["npm_list"] = self.npm_list
        template["thn_list"] = self.thn_list
        template["bld_list"] = self.bld_list
        template["snyk_list"] = self.snyk_list
        template["osvdb_list"] = self.osvdb_list
        return template

    def __unicode__(self):
        return "vulnerabilities"

    def __str__(self):
        return self.vulner_id

