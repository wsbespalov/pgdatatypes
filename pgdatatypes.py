import re
import peewee
from playhouse.postgres_ext import JSONField, ArrayField
from datetime import datetime

database = peewee.PostgresqlDatabase(
    database="updater_db",
    user="admin",
    password="123",
    host="localhost",
    port="5432"
)

def unify_dt(dt):
    return datetime.strptime(dt.strftime('%Y-%m-%d %H:%M:%S'), '%Y-%m-%d %H:%M:%S')

def dt2str(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S')


def str2dt(dts):
    return datetime.strptime(dts, '%Y-%m-%d %H:%M:%S')


def onlyfigits(s):
    return re.sub("\D\.\?", "", s)


def filter_version(version):
    if version == "" or version == "*" or version == "-":
        version = "?"
    return version

class PGDATAMODEL(peewee.Model):
    class Meta:
        database = database
        table_name = "pgdatatypes"

    id = peewee.PrimaryKeyField(null=False)
    vulner_id = peewee.TextField(default="")
    component = peewee.TextField(default="")
    versions = ArrayField(peewee.TextField, default=[])
    vulner_data = JSONField(default=dict(
        cve_ids=[],
        title="",
        description="",
        cwe=[],
        capec=[],
        published="")
    )

    def __str__(self):
        return self.vulner_id


    def save(self, **kwargs):
        with database.transaction():
            if isinstance(self.vulner_data["published"], datetime):
                self.vulner_data["published"] = dt2str(self.vulner_data["published"])
            self.component = str(self.component).lower()
            peewee.Model.save(self, **kwargs)

    @property
    def tojson(self):
        return dict(
            id=self.id,
            vulner_id=self.vulner_id,
            component=self.component,
            versions=self.versions,
            cve_ids=self.vulner_data["cve_ids"],
            title=self.vulner_data["title"],
            description=self.vulner_data["description"],
            published=str2dt(self.vulner_data["published"]),
            cwe=self.vulner_data["cwe"],
            capec=self.vulner_data["capec"]
        )

    def incwe(self, cwe):
        return cwe in self.vulner_data["cwe"]

    def incapec(self, capec):
        return capec in self.vulner_data["capec"]

    def inversions(self, version):
        version = filter_version(onlyfigits(version))
        return version in self.versions

    def append_version(self, version):
        version = filter_version(onlyfigits(version))
        self.versions.append(version)


# TODO: hsahaha

if database.is_closed():
    database.connect()


if PGDATAMODEL.table_exists():
    PGDATAMODEL.drop_table()


if not PGDATAMODEL.table_exists():
    PGDATAMODEL.create_table()


data_template = dict(
    vulner_id="SP:123",
    component="android",
    versions=["6.0"],
    vulner_data=dict(
        cve_ids=["CVE-2018-12345"],
        title="Test vulnerability 1",
        description="Test description 1",
        published=datetime.utcnow(),
        cwe=["CWE-1", "CWE-2"],
        capec=["CAPEC-1"]
    )
)

pgd = PGDATAMODEL.create()
pgd.vulner_id=data_template["vulner_id"]
pgd.component=data_template["component"]
pgd.versions=data_template["versions"]
pgd.vulner_data=data_template["vulner_data"]
pgd.save()


# pgdd_list = (PGDATAMODEL.select().where(PGDATAMODEL.vulner_id == "SP:123"))
pgdd_list = (PGDATAMODEL.select().where(PGDATAMODEL.versions.contains("6.0")))
if len(pgdd_list) > 0:
    print("find one in PG database")
    pgdd = pgdd_list[0]
    print("represent as json")
    print(pgdd.tojson)
    print("check incwe method")
    print(pgdd.incwe("CWE-1"))
    print(pgdd.incwe("CWE-3"))
    print("check inversions")
    print(pgdd.inversions("6.0"))
    print(pgdd.inversions("6.1"))
    print("versions")
    pgdd.append_version("6.1")
    pgdd.append_version("7.?")
    pgdd.save()
    print(pgdd.versions)

if not database.is_closed():
    database.close()
