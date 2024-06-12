# Stock Bot implementing a line bot by TDD
> NYCU-Software-Testing-Final-project

## 股票機器人的功能:

1. 收集即時的股票資訊

2. 分析股票過去的資料

3. 產生短、中、長期的均線圖

4. 計算夏普及威廉指標

---

## 股票機器人API的軟體測試:

1. TDD: Python unittest + Coverage

2. Fuzz testing: Google Atheris

---

## Attach to Testing Introduction of StockAPI 

Will be uploaded AfterWard

---
## 檔案位置:
1. 股票機器人API: 
    * Python 3.6: `Stockbot\stockapi.py`
    * Python 3.10: `Stockbot\stockapi_310.py`

2. 股票機器人Linebot: `Stockbot\stockbot.py`

3. 股票機器人Test Case: `Stockbot\test\*`

4. 股票機器人API FuzzTesting:　`Stockbot\fuzz_test\*`

---

## 測試環境/安裝需求 

* **開發環境：**

  Develop Environment：Python3.6 / 3.10 
  
  Windows：11
  
  Linux WSL：22.04 (Atheris Fuzzing)
  
* **安裝環境需求：**

  Line App (Better Visual effect on phone)

---

## 測試執行

### Clone Repository

```
git clone https://github.com/Jim890227/NYCU-Software-Testing-Final-project.git

cd Stockbot
```

### Install Modules

```
pip install pandas matplotlib twstock mplfinance pyimgur beautifulsoup4 requests
```

---

### Unittest With Coverage.py

#### Install Coverage.py

```
pip install coverage
```

> For Python3.10 or above:

> **Please alter `stockapi_310.py` to `stockapi.py`**

> Because some functions are different between 3.6 and 3.10

1. Run the whole functions in stockapi
   
```
coverage run -m --source=. unittest  discover test -v
```

You will see the screen Like:

![image](https://github.com/Jim890227/NYCU-Software-Testing-Final-project/assets/60705979/50fb8151-7ec5-497d-87f8-df67cb71f2a5)



2. Get report in html type (Better View)
   
```
coverage html
```

3. Get report on terminal
   
```
coverage report
```

---

### Atheris Fuzz Testing

#### **Atheris need to execute in Linux/Mac enviroment!!!!**

#### Install Atheris
```
pip3 install atheris
```

1. Locate to fuzz_test Folder and copy stockapi.py into this Folder
   
```
cd fuzz_test
cp ./../stockapi.py .
```

2. Directly execute the testfile with test_*_fuzzz.py

For example:
```
coverage run -m unittest test_calculate_daily_return_rate_fuzz.py
```

You will see the screen Like:

![image](https://github.com/Jim890227/NYCU-Software-Testing-Final-project/assets/60705979/19309f70-3a23-45d2-bf10-48973674d593)

There are some Known Errors because of third party APIs or Database request:

* imgur ⇒ Upload limit of 50 images per hour

* 台灣證券交易所資料庫(TWSE) ⇒ Request limit of 3 requests every 5 seconds, will be banned if exceeded

---
 
## 實做結果

Reached **100%** coverage on every function in StockAPI

![image](https://github.com/Jim890227/NYCU-Software-Testing-Final-project/assets/60705979/c1125c1f-9221-4fe6-b892-9af7adad4df5)

You can also watch the details on the `Stockbot\htmlcov\index.html` from your Browser!

---

## Demo 畫面

![939c5226-b6b9-4be1-b2dc-9d7272bb9694 (1)](https://github.com/Jim890227/NYCU-Software-Testing-Final-project/assets/60705979/4b393d6c-2cb2-4721-a80f-8f1011ec8254)

---

## Reference

https://docs.python.org/zh-tw/3.10/library/unittest.html

https://coverage.readthedocs.io/en/7.5.3/

https://github.com/google/atheris

https://bandit.readthedocs.io/en/latest/

https://twstock.readthedocs.io/zh-tw/latest/index.html

https://steam.oxxostudio.tw/category/python/example/line-bot.html


