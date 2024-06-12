import datetime as dt
import pandas as pd
import matplotlib.pyplot as plt
import twstock
import mplfinance as mpf
import pyimgur
import requests
from bs4 import BeautifulSoup

class StockAPI:
    def fetch(self, stock_number, year, month):
        now = dt.datetime.now()
        if month > 12 or month < 1 or (year == now.year and month > now.month):
            raise ValueError('Month is invalid.')
        if year > now.year:
            raise ValueError('Year is invalid.')
        if type(stock_number) != str:
            raise TypeError('Stock number is invalid.')
        if (stock_number in twstock.twse) == False:
            raise ValueError('Stock number is invalid.')
        target_stock = stock_number
        stock = twstock.Stock(target_stock)
        data = stock.fetch_from(year, month)
        name_attribute = ['Date', 'Capacity', 'Turnover', 'Open', 'High', 'Low', 'Close', 'Change', 'Transcation']
        df = pd.DataFrame(columns= name_attribute, data=data)
        file_name = f'./data/{target_stock}.csv'
        df.to_csv(file_name)
        return df

    def plot(self, stock_number, day):
        if type(stock_number) != str:
            raise TypeError('Stock number is invalid.')
        if (stock_number in twstock.twse) == False:
            raise ValueError('Stock number is invalid.')
        target_stock = stock_number
        now = dt.datetime.now()
        if day >=20:
            if now.month > 6:
                self.fetch(stock_number, now.year, now.month-6)
            else:
                self.fetch(stock_number, now.year-1, now.month+6)
        else:
            if now.month > 3:
                self.fetch(stock_number, now.year, now.month-3)
            else:
                self.fetch(stock_number, now.year-1, now.month+9)
        df = pd.read_csv(f'./data/{target_stock}.csv', parse_dates=True, index_col=0)
        df.rename(columns={'Turnover':'Volume'}, inplace=True)
        df.index = pd.DatetimeIndex(df['Date'])
        df.loc[:,['MA'+ str(day)]] = df['Close'].rolling(window=day).mean()
        mc = mpf.make_marketcolors(up='r',down='g',inherit=True)
        s  = mpf.make_mpf_style(base_mpf_style='yahoo',marketcolors=mc)
        ap = mpf.make_addplot(df.iloc[21:][['MA'+ str(day)]])
        fig, axes = mpf.plot(df.iloc[21:], type='candle', style=s, figratio=(16,9), xrotation=0, addplot=ap, volume=True,returnfig=True)
        axes[0].set_title(target_stock+f' Stock Analysis ({day}-Day Moving Average)', fontsize=14, fontweight='bold')
        axes[2].set_xlabel('Date', fontweight='bold', loc='center')
        axes[0].set_ylabel('Price', fontweight='bold', loc='center')
        plt.savefig(f'./figure/{target_stock}_{day}-Day Moving Average.png')
        client_id = "12db9599f1922b5"
        path = f'./figure/{target_stock}_{day}-Day Moving Average.png'
        title = f'{target_stock}_{day}-Day Moving Average.png'
        im = pyimgur.Imgur(client_id)
        up_loaded_image = im.upload_image(path, title=title)
        return up_loaded_image.link

    def realtime(self, stock_number):
        if type(stock_number) != str:
            raise TypeError('Stock number is invalid.')
        if (stock_number in twstock.twse) == False:
            raise ValueError('Stock number is invalid.')
        now = dt.datetime.now()
        if now.weekday() >= 0 and now.weekday() <= 4:
            if now.hour == 8:
                raise KeyError('Time is invalid.')
            if now.hour == 7 and now.minute >=50:
                raise KeyError('Time is invalid.')
            if now.hour == 9 and now.minute <=10:
                raise KeyError('Time is invalid.')
        if (stock_number in twstock.twse) == False:
            raise ValueError('Stock number is invalid.')
        stock_data = {
            "name": [],
            "high": [],
            "low": [],
            "latest_trade_price": []
        }
        data = twstock.realtime.get(stock_number)
        df = pd.DataFrame(stock_data)
        if data['realtime']['latest_trade_price'] != '-':
            df = df.append({
                "name": data['info']['name'],
                "high": round(float(data['realtime']['high']),2),
                "low": round(float(data['realtime']['low']),2),
                "latest_trade_price": round(float(data['realtime']['latest_trade_price']),2)
            }, ignore_index=True)
        else:
            df = df.append({
                "name": data['info']['name'],
                "high": round(float(data['realtime']['high']),2),
                "low": round(float(data['realtime']['low']),2),
                "latest_trade_price": '目前沒有此資訊'
            }, ignore_index=True)
        df.to_csv(f'./data/{stock_number}_realtime.csv')
        return df
    def calculate_daily_return_rate(self, stock_number):
        if type(stock_number) != str:
            raise TypeError('Stock number is invalid.')
        if (stock_number in twstock.twse) == False:
            raise ValueError('Stock number is invalid.')
        now = dt.datetime.now()
        start = now - dt.timedelta(days=90)
        stock = twstock.Stock(stock_number)
        data = stock.fetch_from(start.year, start.month)
        name_attribute = ['Date', 'Capacity', 'Turnover', 'Open', 'High', 'Low', 'Close', 'Change', 'Transcation']
        df = pd.DataFrame(columns= name_attribute, data=data)
        df['Daily_Return_Rate'] = df['Close'].pct_change()
        return df[['Daily_Return_Rate']]
    def calculate_sharpe_value(self, stock_number):
        if type(stock_number) != str:
            raise TypeError('Stock number is invalid.')
        if (stock_number in twstock.twse) == False:
            raise ValueError('Stock number is invalid.')
        result = self.calculate_daily_return_rate(stock_number)
        return round(result.mean()/result.std(), 4)
    def calculate_william_value(self, stock_number):
        if type(stock_number) != str:
            raise TypeError('Stock number is invalid.')
        if (stock_number in twstock.twse) == False:
            raise ValueError('Stock number is invalid.')
        now = dt.datetime.now()
        start = now - dt.timedelta(days=30)
        stock = twstock.Stock(stock_number)
        data = stock.fetch_from(start.year, start.month)
        name_attribute = ['Date', 'Capacity', 'Turnover', 'Open', 'High', 'Low', 'Close', 'Change', 'Transcation']
        df = pd.DataFrame(columns= name_attribute, data=data)
        william_value = (df[len(df)-15:len(df)-1]['High'].max() - df.iloc[[-1]]['Close']) / (df[len(df)-15:len(df)-1]['High'].max() - df.iloc[[-1]]['Low']) * 100 * (-1)
        return round(float(william_value), 2)

    def get_month_revenue(self, company_id, year, month):
        year = year - 1911
        url = f'https://mops.twse.com.tw/nas/t21/sii/t21sc03_{year}_{month}_0.html'
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            target_table = soup.find('table')
            if target_table:
                rows = target_table.find_all('tr')[2:]
                for row in rows:
                    columns = row.find_all('td')
                    if columns:
                        fetch_company_id = columns[0].text.strip()
                        if fetch_company_id == company_id:
                            company_name = columns[1].text.strip().encode('latin-1').decode('big5', 'ignore')
                            monthly_revenue = columns[2].text.strip()
                            last_month_revenue = columns[3].text.strip()
                            last_year_month_revenue = columns[4].text.strip()
                            monthly_growth_rate = columns[5].text.strip()
                            last_year_growth_rate = columns[6].text.strip()
                            data = {
                                '公司代號': fetch_company_id,
                                '公司名稱': company_name,
                                '當月營收': monthly_revenue,
                                '上月營收': last_month_revenue,
                                '去年當月營收': last_year_month_revenue,
                                '上月比較增減': monthly_growth_rate,
                                '去年同月增減': last_year_growth_rate
                            }
            return data
        else:
            return response.raise_for_status()


# if __name__ == "__main__":
#     stockapi = StockAPI()
    # stockapi.fetch("2330", 2024, 3) #取得股票的資訊從2024年3月到現在為止 
    # stockapi.plot("2330", 20) #畫5日線圖
    # stockapi.realtime("2330") #得到現在的股價(在有開盤早上7:50-9:05不能用)
    # result = stockapi.calculate_sharpe_value("2330") #計算2330的夏普值
    # data = stockapi.get_month_revenue("2330", 2024, 5)
    # print(data)
    # william_value = stockapi.calculate_william_value("2330")
    # print(william_value)