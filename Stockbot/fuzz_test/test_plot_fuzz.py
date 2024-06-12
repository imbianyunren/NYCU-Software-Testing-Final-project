import unittest
import datetime as dt
import pandas as pd
import atheris
import sys
from stockapi import StockAPI

class TestStockAPIFuzz(unittest.TestCase):

    atheris.instrument_all()

    def setUp(self):
        self.stockapi = StockAPI()
        

    def test_plot_fuzz(self):
        def test_one_input(input_bytes):
            fdp = atheris.FuzzedDataProvider(input_bytes)
            # stock_number = fdp.ConsumeUnicodeNoSurrogates(10)
            stock_number = str(fdp.ConsumeIntInRange(0, 9999)).zfill(4)
            try:
                self.stockapi.plot(stock_number, 5)
            except (ValueError, TypeError):
                pass

        atheris.Setup(sys.argv, test_one_input)
        atheris.Fuzz()

if __name__ == "__main__":
    unittest.main()
