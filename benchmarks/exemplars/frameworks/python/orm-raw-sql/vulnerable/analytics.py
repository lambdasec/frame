import pandas as pd
from sqlalchemy import create_engine

engine = create_engine("postgresql://app@db/shop")


def orders_for(customer):
    df = pd.read_sql("SELECT * FROM orders WHERE customer = '" + customer + "'", engine)  # frame-expect: CWE-89
    return df.to_dict("records")
