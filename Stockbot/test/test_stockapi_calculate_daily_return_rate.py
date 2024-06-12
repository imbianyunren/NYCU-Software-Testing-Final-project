import unittest
from unittest.mock import patch, Mock
import datetime as dt
import pandas as pd
import matplotlib.pyplot as plt
import twstock
import mplfinance as mpf
import pyimgur
import requests
from bs4 import BeautifulSoup
from stockapi import StockAPI
import os

class TestStockAPI(unittest.TestCase):
    
    def setUp(self):
        self.stockapi = StockAPI()
    
    def test_calculate_daily_return_rate_valid_stock(self):
        self.stockapi.fetch('2330', 2024, 3)
        result = self.stockapi.calculate_daily_return_rate('2330')
        self.assertIsInstance(result, pd.DataFrame)
        self.assertIn('Daily_Return_Rate', result.columns)
    
    def test_calculate_daily_return_rate_invalid_stock(self):
        with self.assertRaises(ValueError):
            self.stockapi.calculate_daily_return_rate('123456789')

    def test_calculate_daily_return_rate_invalid_stock_number_type(self):
        with self.assertRaises(TypeError):
            self.stockapi.calculate_daily_return_rate(2330)

# if __name__ == "__main__":
#     unittest.main()
