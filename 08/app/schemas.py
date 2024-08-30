from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, ConfigDict
from pydantic.fields import Field


CVE_ID_PATTERN = r'^CVE-\d{4}-\d{1,5}$'


def get_cve_id_field() -> Field:
    return Field(...,
        pattern=CVE_ID_PATTERN,
        description='id is the unique string with the following format: "CVE-YYYY-N", '
                    'where N is a number between 1 and 99999',
        examples=['CVE-2001-0001', 'CVE-2020-20341']
    )

class CveBaseModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class CveId(CveBaseModel):
    id: str = get_cve_id_field()


class Description(CveBaseModel):
    lang: str
    text: str


class ProblemType(CveBaseModel):
    lang: str
    text: str


class Reference(CveBaseModel):
    name: str
    url: str


class Cve(CveId):
    title: str
    date_published: datetime
    date_updated: datetime
    descriptions: Optional[List[Description]] = None
    problem_types: Optional[List[ProblemType]] = None
    references: List[Reference]

