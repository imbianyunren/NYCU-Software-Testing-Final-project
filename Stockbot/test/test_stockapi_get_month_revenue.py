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
  
    @patch('stockapi.requests.get')
    def test_get_month_revenue_success(self, mock_get):
        # Mock the HTML response from the URL
        mock_html = '''
        <html>
            <body>
                <table>
                    <tr><td>Header</td></tr>
                    <tr><td>Header</td></tr>
                    <tr>
                        <td>1234</td>
                        <td>Company Name</td>
                        <td>1000</td>
                        <td>2000</td>
                        <td>3000</td>
                        <td>10%</td>
                        <td>20%</td>
                    </tr>
                </table>
            </body>
        </html>
        '''
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = mock_html
        mock_get.return_value = mock_response

        # Call the function
        result = self.stockapi.get_month_revenue('1234', 2023, 5)
        
        # Expected result
        expected_result = {
            '公司代號': '1234',
            '公司名稱': 'Company Name',
            '當月營收': '1000',
            '上月營收': '2000',
            '去年當月營收': '3000',
            '上月比較增減': '10%',
            '去年同月增減': '20%'
        }
        
        self.assertEqual(result, expected_result)

    @patch('stockapi.requests.get')
    def test_get_month_revenue_failure(self, mock_get):
        # Mock a failed HTML response
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError
        mock_get.return_value = mock_response
        
        # Call the function and assert that an HTTPError is raised
        with self.assertRaises(requests.exceptions.HTTPError):
            self.stockapi.get_month_revenue('1234', 2023, 5)

# if __name__ == "__main__":
#     unittest.main()
