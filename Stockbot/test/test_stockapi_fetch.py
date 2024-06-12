import unittest
from unittest.mock import patch
import datetime as dt
import pandas as pd
import matplotlib.pyplot as plt
from stockapi import StockAPI
import os

class TestStockAPI(unittest.TestCase):
    
    def setUp(self):
        self.stockapi = StockAPI()
    
    # 取得從指定時間到現在的股票資訊
    # fetch("股票代號", YYYY, MM)
    @patch('twstock.Stock')  # mock twstock.Stock
    def test_fetch_success_csv(self, MockStock):
        mock_data = [
            [dt.datetime(2023, 1, 1), 1000,2000,100,110,90,105,5,10],
            [dt.datetime(2023, 1, 2), 1500,2500,105,115,95,110,5,15],
        ]
        mock_stock_instance = MockStock.return_value
        mock_stock_instance.fetch_from.return_value = mock_data

        stock_api = self.stockapi
        result = stock_api.fetch('2330', 2023, 1)
        
        self.assertIsInstance(result, pd.DataFrame)
        mock_stock_instance.fetch_from.assert_called_once_with(2023, 1)

        # ensure the file be create
        file_name = './data/2330.csv'
        self.assertTrue(os.path.isfile(file_name))
        df = pd.read_csv(file_name)
        if 'Unnamed: 0' in df.columns:
            df = df.drop(columns=['Unnamed: 0'])
        expected_first_row = {
            'Date': '2023-01-01',
            'Capacity': 1000,
            'Turnover': 2000,
            'Open': 100,
            'High': 110,
            'Low': 90,
            'Close': 105,
            'Change': 5,
            'Transcation': 10
        }
        first_row = df.iloc[0].to_dict()
        # 把日期轉為str
        first_row['Date'] = pd.to_datetime(first_row['Date']).strftime('%Y-%m-%d')
        self.assertEqual(first_row, expected_first_row)
        if os.path.isfile(file_name):
            os.remove(file_name)
    
    def test_fetch_invalid_month(self):
        with self.assertRaises(ValueError):
            self.stockapi.fetch("2330", 2024, 13)
        with self.assertRaises(ValueError):
            self.stockapi.fetch("2330", 2024, 0)
        with self.assertRaises(ValueError):
            self.stockapi.fetch("2330", 2024, 8)
    
    def test_fetch_invalid_year(self):
        with self.assertRaises(ValueError):
            self.stockapi.fetch("2330", dt.datetime.now().year + 1, 3)
        
    def test_fetch_invalid_stock_number_type(self):
        with self.assertRaises(TypeError):
            self.stockapi.fetch(2330, 2024, 3)
            
    def test_fetch_invalid_stock(self):
        with self.assertRaises(ValueError):
            self.stockapi.fetch("12345678", 2024, 3)
            

# if __name__ == "__main__":
#     unittest.main()
