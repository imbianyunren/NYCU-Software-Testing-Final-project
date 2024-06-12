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
  
    def test_calculate_sharpe_value_valid_stock(self):
        self.stockapi.fetch('2330', 2024, 3)
        result = self.stockapi.calculate_sharpe_value('2330')
        self.assertIsInstance(result.iloc[0], float)
    
    def test_calculate_sharpe_value_invalid_stock(self):
        with self.assertRaises(ValueError):
            self.stockapi.calculate_sharpe_value('123456789')
    
    def test_calculate_sharpe_value_invalid_stock_number_type(self):
        with self.assertRaises(TypeError):
            self.stockapi.calculate_sharpe_value(2330)     
            
# if __name__ == "__main__":
#     unittest.main()
