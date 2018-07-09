import peewee
from playhouse.postgres_ext import JSONField
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



class PGDATAMODEL(peewee.Model):
    class Meta:
        database = database
        table_name = "pgdatatypes"

    id = peewee.PrimaryKeyField(null=False)
    vulner_id = peewee.TextField(default="")
    vulner_data = JSONField(default=dict(
        cve_id="",
        title="",
        description="",
        cwe=[],
        published="")
    )

    def __str__(self):
        return self.vulner_id


    def save(self, **kwargs):
        with database.transaction():
            peewee.Model.save(self, **kwargs)

    @property
    def tojson(self):
        return dict(
            id=self.id,
            vulner_id=self.vulner_id,
            cve_id=self.vulner_data["cve_id"],
            title=self.vulner_data["title"],
            description=self.vulner_data["description"],
            published=str2dt(self.vulner_data["published"]),
            cwe=self.vulner_data["cwe"]
        )

if database.is_closed():
    database.connect()


if PGDATAMODEL.table_exists():
    PGDATAMODEL.drop_table()


if not PGDATAMODEL.table_exists():
    PGDATAMODEL.create_table()


data_template = dict(
    vulner_id="SP:12345",
    vulner_data=dict(
        cve_id="CVE-2018-12345",
        title="Test vulnerability 1",
        description="Test description 1",
        published=dt2str(datetime.utcnow()),
        cwe=["CWE-1", "CWE-2"]
    )
)

pgd = PGDATAMODEL.create(
    vulner_id=data_template["vulner_id"],
    vulner_data=data_template["vulner_data"]
)

pgdd_list = (PGDATAMODEL.select().where(PGDATAMODEL.vulner_id == "SP:12345"))
if len(pgdd_list) > 0:
    pgdd = pgdd_list[0]
    print(pgdd.tojson)



if not database.is_closed():
    database.close()
