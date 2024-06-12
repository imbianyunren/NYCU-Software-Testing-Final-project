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
            
    def test_calculate_william_value_invalid_stock_number_type(self):
        with self.assertRaises(TypeError):
            self.stockapi.calculate_william_value(2330)
            
    def test_calculate_william_valuecalculate_william_value_invalid_stock_number_value(self):
        with self.assertRaises(ValueError):
            self.stockapi.calculate_william_value('123456789')
    
    @patch('stockapi.twstock.Stock')
    @patch('stockapi.dt')
    def test_calculate_william_value_valid_stock(self, mock_dt, MockStock):
        # Simulate time
        mock_now = dt.datetime(2023, 6, 1)
        mock_dt.datetime.now.return_value = mock_now
        mock_dt.datetime.side_effect = lambda *args, **kw: dt.datetime(*args, **kw)

        # Mock stock data for the past 30 days
        mock_data = [
            [mock_now - dt.timedelta(days=30-i), 1000 + i*100, 2000 + i*100, 100 + i, 110 + i, 90 + i, 105 + i, 5 + i, 10 + i]
            for i in range(30)
        ]

        mock_stock_instance = MockStock.return_value
        mock_stock_instance.fetch_from.return_value = mock_data

        william_value = self.stockapi.calculate_william_value('2330')

        # print("Mock Data (Last 15 Days):")
        # for data in mock_data[-15:-1]:
        #     print(data)
        
        high_max = max([data[4] for data in mock_data[-15:-1]])
        close = mock_data[-1][6]
        low = mock_data[-1][5]
        expected_value = ((high_max - close) / (high_max - low) * 100 * (-1))
        expected_value = round(expected_value, 2)

        # print(f"Expected William Value: {expected_value}, Calculated William Value: {william_value}")

        self.assertEqual(william_value, expected_value) 
        
# if __name__ == "__main__":
#     unittest.main()
