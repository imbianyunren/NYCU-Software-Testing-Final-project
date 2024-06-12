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
    
       
    def test_realtime_invalid_stock_number_type(self):
        with self.assertRaises(TypeError):
            self.stockapi.realtime(2330) 
               
    def test_realtime_invalid_stock(self):
        with self.assertRaises(ValueError):
            self.stockapi.realtime('12345678')
    
    @patch('stockapi.dt')
    def test_realtime_invalid_time1(self, mock_dt):
        # Simulate an invalid time (e.g., during restricted trading hours)
        mock_dt.datetime.now.return_value = dt.datetime(2023, 6, 1, 8, 0)
        with self.assertRaises(KeyError):
            self.stockapi.realtime('2330')
            
    @patch('stockapi.dt')
    def test_realtime_invalid_time2(self, mock_dt):
        # Simulate an invalid time (e.g., during restricted trading hours)
        mock_dt.datetime.now.return_value = dt.datetime(2023, 6, 1, 7,50)
        with self.assertRaises(KeyError):
            self.stockapi.realtime('2330')
    
    @patch('stockapi.dt')
    def test_realtime_invalid_time3(self, mock_dt):
        # Simulate an invalid time (e.g., during restricted trading hours)
        mock_dt.datetime.now.return_value = dt.datetime(2023, 6, 1, 9, 10)
        with self.assertRaises(KeyError):
            self.stockapi.realtime('2330') 
                
    @patch('stockapi.twstock.realtime.get')
    @patch('stockapi.dt')
    def test_realtime_with_latest_trade_price(self, mock_dt, mock_realtime_get):
        # Mock datetime to ensure the correct logic for time checks
        mock_dt.datetime.now.return_value = dt.datetime(2023, 6, 1, 9, 15)

        # Test case when latest_trade_price is available
        mock_realtime_get.return_value = {
            'info': {'name': 'Test Stock'},
            'realtime': {'latest_trade_price': '100', 'high': '105', 'low': '95'}
        }
        result = self.stockapi.realtime('2330')
        self.assertIsInstance(result, pd.DataFrame)
        file_name = './data/2330_realtime.csv'
        self.assertTrue(os.path.isfile(file_name))

        # Verify CSV content
        df = pd.read_csv(file_name)
        self.assertEqual(len(df), 1)  # Ensure one row is written
        self.assertEqual(df.iloc[0]['name'], 'Test Stock')
        self.assertEqual(df.iloc[0]['high'], 105.0)
        self.assertEqual(df.iloc[0]['low'], 95.0)
        self.assertEqual(df.iloc[0]['latest_trade_price'], 100.0)        
        if os.path.isfile(file_name):
            os.remove(file_name)
            
    
    # Test case when latest_trade_price is not available
    @patch('stockapi.twstock.realtime.get')
    @patch('stockapi.dt')
    def test_realtime_without_latest_trade_price(self, mock_dt, mock_realtime_get):   
        mock_dt.datetime.now.return_value = dt.datetime(2023, 6, 1, 9, 15)     
        mock_realtime_get.return_value = {
            'info': {'name': 'Test Stock'},
            'realtime': {'latest_trade_price': '-', 'high': '105', 'low': '95'}
        }
        result = self.stockapi.realtime('2330')
        self.assertIsInstance(result, pd.DataFrame)
        file_name = './data/2330_realtime.csv'
        self.assertTrue(os.path.isfile(file_name))
        # Verify CSV content
        df = pd.read_csv(file_name)
        self.assertEqual(len(df), 1)  # Ensure one row is written
        self.assertEqual(df.iloc[0]['name'], 'Test Stock')
        self.assertEqual(df.iloc[0]['high'], 105.0)
        self.assertEqual(df.iloc[0]['low'], 95.0)
        self.assertEqual(df.iloc[0]['latest_trade_price'], '目前沒有此資訊')
        if os.path.isfile(file_name):
            os.remove(file_name)  
    
# if __name__ == "__main__":
#     unittest.main()
