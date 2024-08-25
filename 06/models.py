import datetime
from typing import List
from sqlalchemy.schema import CreateTable, Identity
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import DeclarativeBase, relationship, Mapped, mapped_column
from sqlalchemy import String, TIMESTAMP, ForeignKey, Integer, Column, Index
from sqlalchemy import Table, UniqueConstraint
from sqlalchemy.dialects import postgresql

CVE_ID_LENGTH = 20

def foreign_key_cve():
    return mapped_column(String(length=CVE_ID_LENGTH), ForeignKey("cve.id"), nullable=False)


class Base(AsyncAttrs, DeclarativeBase):
    pass


class Cve(Base):
    __tablename__ = "cve"

    id: Mapped[str] = Column(
        String(length=CVE_ID_LENGTH),
        nullable=False,
        primary_key=True,
    )
    date_published: Mapped[datetime.datetime] = Column(
        TIMESTAMP(timezone=True),
        nullable=False
    )
    date_updated: Mapped[datetime.datetime] = Column(
        TIMESTAMP(timezone=True),
        nullable=False
    )
    title: Mapped[str] = Column(
        String(),
        nullable=False,
        default='n/a'
    )
    descriptions: Mapped[List["Description"]] = relationship(back_populates="cve", cascade="all, delete-orphan")
    problem_types: Mapped[List["ProblemType"]] = relationship(back_populates="cve", cascade="all, delete-orphan")
    references: Mapped[List["Reference"]] = relationship(back_populates="cve", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_cve_published", "date_published"),
        Index("idx_cve_updated", "date_updated"),
    )

    def __repr__(self) -> str:
        return f"<Cve(id={self.id}>"


def primary_key():
    return mapped_column(Integer(), Identity(start=1), autoincrement=True, primary_key=True, nullable=False)


def lang():
    return mapped_column(String(length=5), nullable=False)


class Description(Base):
    __tablename__ = "description"

    id: Mapped[int] = primary_key()
    cve_id: Mapped[str] = foreign_key_cve()
    lang: Mapped[str] = lang()
    text: Mapped[str] = mapped_column(String(), nullable=False)
    cve: Mapped["Cve"] = relationship(back_populates="descriptions")


class ProblemType(Base):
    __tablename__ = 'problem_type'

    id: Mapped[int] = primary_key()
    cve_id: Mapped[str] = foreign_key_cve()
    lang: Mapped[str] = lang()
    text: Mapped[str] = mapped_column(String(), nullable=False)
    cve: Mapped["Cve"] = relationship(back_populates="problem_types")


association_table = Table(
    "reference_tag",
    Base.metadata,
    Column("id_ref", ForeignKey("reference.id"), primary_key=True, nullable=False),
    Column("id_tag", ForeignKey("tag.id"), primary_key=True, nullable=False),
)


class Tag(Base):
    __tablename__ = 'tag'

    id: Mapped[int] = primary_key()
    name: Mapped[str] = mapped_column(String(), nullable=False)
    references: Mapped[List["Reference"]] = relationship(
        secondary=association_table, back_populates="tags"
    )

    __table_args__ = (
        Index("idx_tag_name", "name"),
        UniqueConstraint("name"),
    )

    def __repr__(self) -> str:
        return f"<Tag(name={self.name}>"


class Reference(Base):
    __tablename__ = 'reference'

    id: Mapped[int] = mapped_column(Integer(), autoincrement=True, primary_key=True, nullable=False)
    name: Mapped[str] = mapped_column(String(), nullable=False)
    url: Mapped[str] = mapped_column(String(), nullable=False)
    tags: Mapped[List[Tag]] = relationship(
        secondary=association_table, back_populates="references"
    )
    cve_id: Mapped[str] = foreign_key_cve()
    cve: Mapped["Cve"] = relationship(back_populates="references")


if __name__ == '__main__':
    print(CreateTable(Cve.__table__).compile(dialect=postgresql.dialect()))
    print(CreateTable(Reference.__table__).compile(dialect=postgresql.dialect()))
    print(CreateTable(Description.__table__).compile(dialect=postgresql.dialect()))
    print(CreateTable(association_table).compile(dialect=postgresql.dialect()))