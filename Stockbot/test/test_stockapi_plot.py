import unittest
from unittest.mock import patch, Mock
import datetime as dt
import pandas as pd
import matplotlib.pyplot as plt
from stockapi import StockAPI
import os

class TestStockAPI(unittest.TestCase):
    
    def setUp(self):
        self.stockapi = StockAPI()
            
    # day <= 20
    @patch('stockapi.dt')
    def test_plot_sucess_image_m_more_than_3(self, mock_dt):
        # Simulate time
        # month > 3
        mock_dt.datetime.now.return_value = dt.datetime(2023, 4, 1, 12, 0)
        stock_api = self.stockapi
        result = stock_api.plot('2330', 15)
        file_name = './figure/2330_15-Day Moving Average.png'
        self.assertTrue(os.path.isfile(file_name))
        # 確認連結是imgur開頭 且符合格式
        self.assertTrue(result.startswith("https://i.imgur.com/"))
        self.assertTrue(result.endswith(".png"))
        self.assertRegex(result, r'^https://i\.imgur\.com/[a-zA-Z0-9]+\.png$')
        if os.path.isfile('./data/2330.csv'):
            os.remove('./data/2330.csv')
        if os.path.isfile(file_name):
            os.remove(file_name)
    
    # day <= 20
    @patch('stockapi.dt')
    def test_plot_sucess_image_m_less_than_3(self, mock_dt):            
        # month < 3 
        mock_dt.datetime.now.return_value = dt.datetime(2023, 1, 1, 12, 0)
        stock_api = self.stockapi
        result = stock_api.plot('2330', 15)
        file_name = './figure/2330_15-Day Moving Average.png'
        self.assertTrue(os.path.isfile(file_name))
        # 確認連結是imgur開頭 且符合格式
        self.assertTrue(result.startswith("https://i.imgur.com/"))
        self.assertTrue(result.endswith(".png"))
        self.assertRegex(result, r'^https://i\.imgur\.com/[a-zA-Z0-9]+\.png$')
        if os.path.isfile('./data/2330.csv'):
            os.remove('./data/2330.csv')
        if os.path.isfile(file_name):
            os.remove(file_name)
    
    # day <= 20
    @patch('stockapi.dt')
    def test_plot_sucess_image_m_more_than_6(self, mock_dt):
        # month > 6 
        mock_dt.datetime.now.return_value = dt.datetime(2023, 7, 1, 12, 0)
        stock_api = self.stockapi
        result = stock_api.plot('2330', 50)
        # check the file establish succeed
        file_name = './figure/2330_50-Day Moving Average.png'
        self.assertTrue(os.path.isfile(file_name))
        self.assertTrue(result.startswith("https://i.imgur.com/"))
        self.assertTrue(result.endswith(".png"))
        self.assertRegex(result, r'^https://i\.imgur\.com/[a-zA-Z0-9]+\.png$')
        if os.path.isfile('./data/2330.csv'):
            os.remove('./data/2330.csv')
        if os.path.isfile(file_name):
            os.remove(file_name)
    
    # day >= 20
    @patch('stockapi.dt')
    def test_plot_sucess_image_m_less_than_6(self, mock_dt):            
        # month < 6 
        mock_dt.datetime.now.return_value = dt.datetime(2023, 1, 1, 12, 0)
        stock_api = self.stockapi
        result = stock_api.plot('2330', 50)
        # check the file establish succeed
        file_name = './figure/2330_50-Day Moving Average.png'
        self.assertTrue(os.path.isfile(file_name))
        self.assertTrue(result.startswith("https://i.imgur.com/"))
        self.assertTrue(result.endswith(".png"))
        self.assertRegex(result, r'^https://i\.imgur\.com/[a-zA-Z0-9]+\.png$')
        if os.path.isfile('./data/2330.csv'):
            os.remove('./data/2330.csv')
        if os.path.isfile(file_name):
            os.remove(file_name)
            
    def test_plot_invalid_stock(self):
        with self.assertRaises(ValueError):
            self.stockapi.plot("12345678", 15)
        with self.assertRaises(TypeError):
            self.stockapi.plot(2330, 15)
            

# if __name__ == "__main__":
#     unittest.main()
