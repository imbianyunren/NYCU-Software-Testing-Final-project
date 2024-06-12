from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy

# 載入 LINE Message API 相關函式庫
from linebot import LineBotApi, WebhookHandler
from linebot.exceptions import InvalidSignatureError
from linebot.models import MessageEvent, TextMessage, TextSendMessage, ImageSendMessage, TemplateSendMessage, CarouselTemplate, CarouselColumn, URIAction, ButtonsTemplate, MessageAction
import datetime as dt
import pygsheets
import pandas as pd
import twstock
import mplfinance as mpf
import matplotlib.pyplot as plt
import pyimgur
import matplotlib
from bs4 import BeautifulSoup
import requests

matplotlib.use('agg')

app = Flask(__name__)

app.config['SQLACLCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///User.sqlite3'

db = SQLAlchemy(app)


f = open('token.txt', 'r')
text = []
for line in f.readlines():
    text.append(line)
access_token = text[0].split(' ')[2]
access_token = access_token[0:len(access_token)-1] #把'\n'去掉
secret = text[1].split(' ')[1]


line_bot_api = LineBotApi(access_token)              # 確認 token 是否正確
handler = WebhookHandler(secret)                     # 確認 secret 是否正確


@app.route("/", methods=['POST'])
def linebot():
    body = request.get_data(as_text=True)                    # 取得收到的訊息內容
    try:
        signature = request.headers['X-Line-Signature']      # 加入回傳的 headers
        handler.handle(body, signature)                      # 綁定訊息回傳的相關資訊
    except:
        print(body)                                          # 如果發生錯誤，印出收到的內容
    return 'OK'                                              # 驗證 Webhook 使用，不能省略

class User(db.Model):
    __tablename__ = "user"
    _id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    userid = db.Column(db.String(100), nullable=False)

    def __init__(self, name, userid):
        self.name = name
        self.userid = userid

@handler.add(MessageEvent, message=TextMessage)
def handle_message(event):
    if event.message.text == '初次使用':
        user_id = event.source.user_id
        profile = line_bot_api.get_profile(user_id)
        name = profile.display_name
        user = db.session.query(User).filter(User.userid == user_id).first()
        if user is None:
            new_data = User(name, user_id)
            db.session.add(new_data)
            db.session.commit()
            line_bot_api.reply_message(event.reply_token, TemplateSendMessage(
                alt_text='CarouselTemplate',
                template=CarouselTemplate(
                    columns=[
                        CarouselColumn(
                            title='股票調查',
                            text='第一次使用請幫我填寫',
                            actions=[
                                URIAction(
                                    label='表單網址',
                                    uri='https://forms.gle/qMY4nb9Tw2RZKW7V8'
                                )
                            ],
                        )
                    ]
                ),
            ))
        else:
            message = TextSendMessage(text='您已設定過!\n請點選資料更新來進行資料更新~')
            line_bot_api.reply_message(event.reply_token, message)
    elif event.message.text == '資料更新':
        user_id = event.source.user_id
        profile = line_bot_api.get_profile(user_id)
        name = profile.display_name
        user = db.session.query(User).filter(User.userid == user_id).first()
        if user is None:
            message = TextSendMessage(text='請先點選主選單中的初次使用，以進行基本資料設定 謝謝!')
            line_bot_api.reply_message(event.reply_token, message)
        else:
            if user.name != name:
                db.session.query(User).filter(User.userid == user_id).update({User.name: name})
                db.session.commit()
        line_bot_api.reply_message(event.reply_token, TemplateSendMessage(
                alt_text='CarouselTemplate',
                template=CarouselTemplate(
                    columns=[
                        CarouselColumn(
                            title='股票調查',
                            text='請重新幫我填寫',
                            actions=[
                                URIAction(
                                    label='表單網址',
                                    uri='https://forms.gle/qMY4nb9Tw2RZKW7V8'
                                )
                            ],
                        )
                    ]
                ),
            ))
        
    elif event.message.text == '持股均線圖':
        user_id = event.source.user_id
        profile = line_bot_api.get_profile(user_id)
        name = profile.display_name
        user = db.session.query(User).filter(User.userid == user_id).first()
        if user is None:
            message = TextSendMessage(text='請先點選主選單中的初次使用，以進行基本資料設定 謝謝!')
            line_bot_api.reply_message(event.reply_token, message)
        else:
            if user.name != name:
                db.session.query(User).filter(User.userid == user_id).update({User.name: name})
                db.session.commit()
        line_bot_api.reply_message(event.reply_token, TemplateSendMessage(
            alt_text='ButtonsTemplate',
            template=ButtonsTemplate(
                title='股票均線圖',
                text='選擇想要的種類',
                actions=[
                    MessageAction(
                        label='5日均線圖',
                        text='產生5日均線圖'
                    ),
                    MessageAction(
                        label='10日均線圖',
                        text='產生10日均線圖'
                    ),
                    MessageAction(
                        label='20日均線圖',
                        text='產生20日均線圖'
                    ),
                    MessageAction(
                        label='30日均線圖',
                        text='產生30日均線圖'
                    ),
                ]
            )
        ))
    elif event.message.text == '產生5日均線圖':
        reply_msg = []
        user_id = event.source.user_id
        profile = line_bot_api.get_profile(user_id)
        name = profile.display_name
        user = db.session.query(User).filter(User.userid == user_id).first()
        if user is None:
            message = TextSendMessage(text='請先點選主選單中的初次使用，以進行基本資料設定 謝謝!')
            line_bot_api.reply_message(event.reply_token, message)
        else:
            if user.name != name:
                db.session.query(User).filter(User.userid == user_id).update({User.name: name})
                db.session.commit()
        gc = pygsheets.authorize(service_file = './certificate.json')
        file = gc.open_by_url('https://docs.google.com/spreadsheets/d/1YFahymzBkdwjbhLxC_KkC5ZIAQuGP-RgY44iO5dwQ4A/edit?resourcekey#gid=233377342')
        sheet = file[0]
        df = pd.DataFrame(sheet.get_all_records())
        field_list = ['水泥','食品','塑膠','紡織纖維','電機機械','電器電纜','化學','生技醫療','玻璃','造紙','鋼鐵','橡膠','汽車','半導體','電腦','光電','通信','電子零組件','電子通路','資訊','其他電子','建材','航運','觀光','金融','貿易百貨','油電燃氣','綠能環保','數位雲端','運動休閒','居家生活','其他']
        stock = df[df['名字'] == user.name]
        result = []
        img_url = []
        for fieid in field_list:
            data = str(stock.iloc[[-1]][fieid])
            end = data.find('\n')
            data = data[5:end]
            if ',' in data:
                temp = data.split(', ')
                for k in temp:
                    result.append(k)
            elif data != '':
                result.append(data)
        flag = 0
        for j in result:
            temp = j.split(' ')
            stock_number = temp[1]
            try:
                img_url.append(plot(stock_number, 5))
            except KeyError or TypeError or ValueError:
                flag = 1
                print('Error occur')
                break
        for k in img_url:
            if flag == 0:
                reply_msg.append(ImageSendMessage(original_content_url=k, preview_image_url=k))
            else:
                reply_msg.append(TextSendMessage(text='目前此功能無法使用'))
        line_bot_api.reply_message(event.reply_token, reply_msg)
    elif event.message.text == '產生10日均線圖':
        reply_msg = []
        user_id = event.source.user_id
        profile = line_bot_api.get_profile(user_id)
        name = profile.display_name
        user = db.session.query(User).filter(User.userid == user_id).first()
        if user is None:
            message = TextSendMessage(text='請先點選主選單中的初次使用，以進行基本資料設定 謝謝!')
            line_bot_api.reply_message(event.reply_token, message)
        else:
            if user.name != name:
                db.session.query(User).filter(User.userid == user_id).update({User.name: name})
                db.session.commit()
        gc = pygsheets.authorize(service_file = './certificate.json')
        file = gc.open_by_url('https://docs.google.com/spreadsheets/d/1YFahymzBkdwjbhLxC_KkC5ZIAQuGP-RgY44iO5dwQ4A/edit?resourcekey#gid=233377342')
        sheet = file[0]
        df = pd.DataFrame(sheet.get_all_records())
        field_list = ['水泥','食品','塑膠','紡織纖維','電機機械','電器電纜','化學','生技醫療','玻璃','造紙','鋼鐵','橡膠','汽車','半導體','電腦','光電','通信','電子零組件','電子通路','資訊','其他電子','建材','航運','觀光','金融','貿易百貨','油電燃氣','綠能環保','數位雲端','運動休閒','居家生活','其他']
        stock = df[df['名字'] == user.name]
        result = []
        img_url = []
        for fieid in field_list:
            data = str(stock.iloc[[-1]][fieid])
            end = data.find('\n')
            data = data[5:end]
            if ',' in data:
                temp = data.split(', ')
                for k in temp:
                    result.append(k)
            elif data != '':
                result.append(data)
        flag = 0
        for j in result:
            temp = j.split(' ')
            stock_number = temp[1]
            try:
                img_url.append(plot(stock_number, 10))
            except KeyError or TypeError or ValueError:
                flag = 1
                print('Error occur')
                break
        for k in img_url:
            if flag == 0:
                reply_msg.append(ImageSendMessage(original_content_url=k, preview_image_url=k))
            else:
                reply_msg.append(TextSendMessage(text='目前此功能無法使用'))
        line_bot_api.reply_message(event.reply_token, reply_msg)
    elif event.message.text == '產生20日均線圖':
        reply_msg = []
        user_id = event.source.user_id
        profile = line_bot_api.get_profile(user_id)
        name = profile.display_name
        user = db.session.query(User).filter(User.userid == user_id).first()
        if user is None:
            message = TextSendMessage(text='請先點選主選單中的初次使用，以進行基本資料設定 謝謝!')
            line_bot_api.reply_message(event.reply_token, message)
        else:
            if user.name != name:
                db.session.query(User).filter(User.userid == user_id).update({User.name: name})
                db.session.commit()
        gc = pygsheets.authorize(service_file = './certificate.json')
        file = gc.open_by_url('https://docs.google.com/spreadsheets/d/1YFahymzBkdwjbhLxC_KkC5ZIAQuGP-RgY44iO5dwQ4A/edit?resourcekey#gid=233377342')
        sheet = file[0]
        df = pd.DataFrame(sheet.get_all_records())
        field_list = ['水泥','食品','塑膠','紡織纖維','電機機械','電器電纜','化學','生技醫療','玻璃','造紙','鋼鐵','橡膠','汽車','半導體','電腦','光電','通信','電子零組件','電子通路','資訊','其他電子','建材','航運','觀光','金融','貿易百貨','油電燃氣','綠能環保','數位雲端','運動休閒','居家生活','其他']
        stock = df[df['名字'] == user.name]
        result = []
        img_url = []
        for fieid in field_list:
            data = str(stock.iloc[[-1]][fieid])
            end = data.find('\n')
            data = data[5:end]
            if ',' in data:
                temp = data.split(', ')
                for k in temp:
                    result.append(k)
            elif data != '':
                result.append(data)
        flag = 0
        for j in result:
            temp = j.split(' ')
            stock_number = temp[1]
            try:
                img_url.append(plot(stock_number, 20))
            except KeyError or TypeError or ValueError:
                flag = 1
                print('Error occur')
                break
        for k in img_url:
            if flag == 0:
                reply_msg.append(ImageSendMessage(original_content_url=k, preview_image_url=k))
            else:
                reply_msg.append(TextSendMessage(text='目前此功能無法使用'))
        line_bot_api.reply_message(event.reply_token, reply_msg)
    elif event.message.text == '產生30日均線圖':
        reply_msg = []
        user_id = event.source.user_id
        profile = line_bot_api.get_profile(user_id)
        name = profile.display_name
        user = db.session.query(User).filter(User.userid == user_id).first()
        if user is None:
            message = TextSendMessage(text='請先點選主選單中的初次使用，以進行基本資料設定 謝謝!')
            line_bot_api.reply_message(event.reply_token, message)
        else:
            if user.name != name:
                db.session.query(User).filter(User.userid == user_id).update({User.name: name})
                db.session.commit()
        gc = pygsheets.authorize(service_file = './certificate.json')
        file = gc.open_by_url('https://docs.google.com/spreadsheets/d/1YFahymzBkdwjbhLxC_KkC5ZIAQuGP-RgY44iO5dwQ4A/edit?resourcekey#gid=233377342')
        sheet = file[0]
        df = pd.DataFrame(sheet.get_all_records())
        field_list = ['水泥','食品','塑膠','紡織纖維','電機機械','電器電纜','化學','生技醫療','玻璃','造紙','鋼鐵','橡膠','汽車','半導體','電腦','光電','通信','電子零組件','電子通路','資訊','其他電子','建材','航運','觀光','金融','貿易百貨','油電燃氣','綠能環保','數位雲端','運動休閒','居家生活','其他']
        stock = df[df['名字'] == user.name]
        result = []
        img_url = []
        for fieid in field_list:
            data = str(stock.iloc[[-1]][fieid])
            end = data.find('\n')
            data = data[5:end]
            if ',' in data:
                temp = data.split(', ')
                for k in temp:
                    result.append(k)
            elif data != '':
                result.append(data)
        flag = 0
        for j in result:
            temp = j.split(' ')
            stock_number = temp[1]
            try:
                img_url.append(plot(stock_number, 30))
            except KeyError or TypeError or ValueError:
                flag = 1
                print('Error occur')
                break
        for k in img_url:
            if flag == 0:
                reply_msg.append(ImageSendMessage(original_content_url=k, preview_image_url=k))
            else:
                reply_msg.append(TextSendMessage(text='目前此功能無法使用'))
        line_bot_api.reply_message(event.reply_token, reply_msg)
    elif event.message.text == '持股健檢':
        reply_msg = []
        user_id = event.source.user_id
        profile = line_bot_api.get_profile(user_id)
        name = profile.display_name
        user = db.session.query(User).filter(User.userid == user_id).first()
        if user is None:
            message = TextSendMessage(text='請先點選主選單中的初次使用，以進行基本資料設定 謝謝!')
            line_bot_api.reply_message(event.reply_token, message)
        else:
            if user.name != name:
                db.session.query(User).filter(User.userid == user_id).update({User.name: name})
                db.session.commit()
        gc = pygsheets.authorize(service_file = './certificate.json')
        file = gc.open_by_url('https://docs.google.com/spreadsheets/d/1YFahymzBkdwjbhLxC_KkC5ZIAQuGP-RgY44iO5dwQ4A/edit?resourcekey#gid=233377342')
        sheet = file[0]
        df = pd.DataFrame(sheet.get_all_records())
        field_list = ['水泥','食品','塑膠','紡織纖維','電機機械','電器電纜','化學','生技醫療','玻璃','造紙','鋼鐵','橡膠','汽車','半導體','電腦','光電','通信','電子零組件','電子通路','資訊','其他電子','建材','航運','觀光','金融','貿易百貨','油電燃氣','綠能環保','數位雲端','運動休閒','居家生活','其他']
        stock = df[df['名字'] == user.name]
        result = []
        for fieid in field_list:
            data = str(stock.iloc[[-1]][fieid])
            end = data.find('\n')
            data = data[5:end]
            if ',' in data:
                temp = data.split(', ')
                for k in temp:
                    result.append(k)
            elif data != '':
                result.append(data)
        flag = 0
        for j in result:
            temp = j.split(' ')
            stock_number = temp[1]
            try:
                sharpe_value_res = calculate_sharpe_value(stock_number)
                william_value_res = calculate_william_value(stock_number)
            except TypeError or ValueError:
                flag = 1
                break
            message = f'公司: {temp[0]}\n股票代號: {stock_number}\n夏普指標: {sharpe_value_res}\n威廉指標: {william_value_res}'
            reply_msg.append(TextSendMessage(text=message))
        if flag == 0:
            line_bot_api.reply_message(event.reply_token, reply_msg)
        else:
            line_bot_api.reply_message(event.reply_token, TextSendMessage(text='目前此功能無法使用'))
    elif event.message.text == '持股即時資訊':
        reply_msg = []
        user_id = event.source.user_id
        profile = line_bot_api.get_profile(user_id)
        name = profile.display_name
        user = db.session.query(User).filter(User.userid == user_id).first()
        if user is None:
            message = TextSendMessage(text='請先點選主選單中的初次使用，以進行基本資料設定 謝謝!')
            line_bot_api.reply_message(event.reply_token, message)
        else:
            if user.name != name:
                db.session.query(User).filter(User.userid == user_id).update({User.name: name})
                db.session.commit()
        gc = pygsheets.authorize(service_file = './certificate.json')
        file = gc.open_by_url('https://docs.google.com/spreadsheets/d/1YFahymzBkdwjbhLxC_KkC5ZIAQuGP-RgY44iO5dwQ4A/edit?resourcekey#gid=233377342')
        sheet = file[0]
        df = pd.DataFrame(sheet.get_all_records())
        field_list = ['水泥','食品','塑膠','紡織纖維','電機機械','電器電纜','化學','生技醫療','玻璃','造紙','鋼鐵','橡膠','汽車','半導體','電腦','光電','通信','電子零組件','電子通路','資訊','其他電子','建材','航運','觀光','金融','貿易百貨','油電燃氣','綠能環保','數位雲端','運動休閒','居家生活','其他']
        stock = df[df['名字'] == user.name]
        result = []
        for fieid in field_list:
            data = str(stock.iloc[[-1]][fieid])
            end = data.find('\n')
            data = data[5:end]
            if ',' in data:
                temp = data.split(', ')
                for k in temp:
                    result.append(k)
            elif data != '':
                result.append(data)
        flag = 0
        result_text = ''
        for j in result:
            temp = j.split(' ')
            stock_number = temp[1]
            try:
                df_result = realtime(stock_number)
            except KeyError or TypeError or ValueError:
                print('Error occur')
                flag = 1
                break
            if df_result['realtime']['latest_trade_price'] == '-':
                text = '{name}\n目前股價為: 目前無此資訊\n今天最高價為: {high}\n今天最低價為: {low}\n'.format(name=df_result['info']['name'], high=round(float(df_result['realtime']['high']),2), low=round(float(df_result['realtime']['low']),2))
            else:
                text = '{name}\n目前股價為: {latest_price}\n今天最高價為: {high}\n今天最低價為: {low}\n'.format(name=df_result['info']['name'], latest_price=round(float(df_result['realtime']['latest_trade_price']),2), high=round(float(df_result['realtime']['high']),2), low=round(float(df_result['realtime']['low']),2))
            result_text = result_text + text
        if flag == 0:
            message = TextSendMessage(text=result_text)
            line_bot_api.reply_message(event.reply_token, message)
        else:
            message = TextSendMessage(text='目前此功能無法使用')
            line_bot_api.reply_message(event.reply_token, message)
    elif event.message.text == '持股公司月營收':
        user_id = event.source.user_id
        profile = line_bot_api.get_profile(user_id)
        name = profile.display_name
        user = db.session.query(User).filter(User.userid == user_id).first()
        if user is None:
            message = TextSendMessage(text='請先點選主選單中的初次使用，以進行基本資料設定 謝謝!')
            line_bot_api.reply_message(event.reply_token, message)
        else:
            if user.name != name:
                db.session.query(User).filter(User.userid == user_id).update({User.name: name})
                db.session.commit()
        gc = pygsheets.authorize(service_file = './certificate.json')
        file = gc.open_by_url('https://docs.google.com/spreadsheets/d/1YFahymzBkdwjbhLxC_KkC5ZIAQuGP-RgY44iO5dwQ4A/edit?resourcekey#gid=233377342')
        sheet = file[0]
        df = pd.DataFrame(sheet.get_all_records())
        field_list = ['水泥','食品','塑膠','紡織纖維','電機機械','電器電纜','化學','生技醫療','玻璃','造紙','鋼鐵','橡膠','汽車','半導體','電腦','光電','通信','電子零組件','電子通路','資訊','其他電子','建材','航運','觀光','金融','貿易百貨','油電燃氣','綠能環保','數位雲端','運動休閒','居家生活','其他']
        stock = df[df['名字'] == user.name]
        result = []
        for fieid in field_list:
            data = str(stock.iloc[[-1]][fieid])
            end = data.find('\n')
            data = data[5:end]
            if ',' in data:
                temp = data.split(', ')
                for k in temp:
                    result.append(k)
            elif data != '':
                result.append(data)
        flag = 0
        result_msg = []
        now = dt.datetime.now()
        for j in result:
            temp = j.split(' ')
            stock_number = temp[1]
            result_text = ''
            try:
                df_result = get_month_revenue(stock_number, now.year, now.month-1)
            except requests.exceptions.HTTPError:
                flag = 1
                break
            text = '{name}\n股票代號: {stock_number}\n這個月營收: {this_month_revenue}\n上個月營收: {last_month_revenue}\n'.format(name=temp[0], stock_number=stock_number, this_month_revenue=df_result['當月營收'], last_month_revenue=df_result['上月營收'])
            result_text = result_text + text
            if df_result['上月比較增減'][0] == '-':
                text = '這個月營收比上個月衰退{value}%\n'.format(value=df_result['上月比較增減'][1:])
                result_text = result_text + text
            else:
                text = '這個月營收比上個月成長{value}%\n'.format(value=df_result['上月比較增減'])
                result_text = result_text + text
            if df_result['去年同月增減'][0] == '-':
                text = '這個月營收比去年同月衰退{value}%\n'.format(value=df_result['去年同月增減'][1:])
                result_text = result_text + text
            else:
                text = '這個月營收比去年同月成長{value}%'.format(value=df_result['去年同月增減'])
                result_text = result_text + text
            result_msg.append(TextMessage(text=result_text))
        if flag == 0:
            line_bot_api.reply_message(event.reply_token, result_msg)
        else:
            message = TextSendMessage(text='目前此功能無法使用')
            line_bot_api.reply_message(event.reply_token, message)

    else:
        message = TextSendMessage(text='請選擇主選單中的功能')
        line_bot_api.reply_message(event.reply_token, message)
        return '請選擇主選單中的功能'

@app.route('/autopushdata')  #在固定時間自動推播訊息  
def getrealtimedata():
    user = User.query.all()
    gc = pygsheets.authorize(service_file = './certificate.json')
    file = gc.open_by_url('https://docs.google.com/spreadsheets/d/1YFahymzBkdwjbhLxC_KkC5ZIAQuGP-RgY44iO5dwQ4A/edit?resourcekey#gid=233377342')
    sheet = file[0]
    df = pd.DataFrame(sheet.get_all_records())
    field_list = ['水泥','食品','塑膠','紡織纖維','電機機械','電器電纜','化學','生技醫療','玻璃','造紙','鋼鐵','橡膠','汽車','半導體','電腦','光電','通信','電子零組件','電子通路','資訊','其他電子','建材','航運','觀光','金融','貿易百貨','油電燃氣','綠能環保','數位雲端','運動休閒','居家生活','其他']
    for i in user:
        stock = df[df['名字'] == i.name]
        result = []
        result_text = ''
        flag = 0
        for fieid in field_list:
            data = str(stock.iloc[[-1]][fieid])
            end = data.find('\n')
            data = data[5:end]
            if ',' in data:
                temp = data.split(', ')
                for k in temp:
                    result.append(k)
            elif data != '':
                result.append(data)
        for j in result:
            temp = j.split(' ')
            stock_number = temp[1]
            try:
                df_result = realtime(stock_number)
            except KeyError or TypeError or ValueError:
                print('Error occur')
                flag = 1
                break
            if df_result['realtime']['latest_trade_price'] == '-':
                text = '{name}\n目前股價為: 目前無此資訊\n今天最高價為: {high}\n今天最低價為: {low}\n'.format(name=df_result['info']['name'], high=round(float(df_result['realtime']['high']),2), low=round(float(df_result['realtime']['low']),2))
            else:
                text = '{name}\n目前股價為: {latest_price}\n今天最高價為: {high}\n今天最低價為: {low}\n'.format(name=df_result['info']['name'], latest_price=round(float(df_result['realtime']['latest_trade_price']),2), high=round(float(df_result['realtime']['high']),2), low=round(float(df_result['realtime']['low']),2))
            result_text = result_text + text
        if flag == 0:
            message = TextSendMessage(text=result_text)
            line_bot_api.push_message(i.userid, message)
        else:
            message = TextSendMessage(text='目前此功能無法使用')
            line_bot_api.push_message(i.userid, message)
    return 'OK'

def realtime(stock_number):
    if type(stock_number) != str:
        raise TypeError('Stock number is invalid.')
    if stock_number in twstock.twse == False:
        raise ValueError('Stock number is invalid.')
    now = dt.datetime.now()
    if now.weekday() >= 0 and now.weekday() <= 4:
        if now.hour == 8:
            raise KeyError('Time is invalid.')
        if now.hour == 7 and now.minute >=50:
            raise KeyError('Time is invalid.')
        if now.hour == 9 and now.minute <=5:
            raise KeyError('Time is invalid.')
    data = twstock.realtime.get(stock_number)
    return data

def plot(stock_number, day):
    if type(stock_number) != str:
        raise TypeError('Stock number is invalid.')
    if stock_number in twstock.twse == False:
        raise ValueError('Stock number is invalid.')
    target_stock = stock_number
    now = dt.datetime.now()
    if day >=20:
        if now.month > 6:
            fetch(stock_number, now.year, now.month-6)
        else:
            fetch(stock_number, now.year-1, now.month+6)
    else:
        if now.month > 3:
            fetch(stock_number, now.year, now.month-3)
        else:
            fetch(stock_number, now.year-1, now.month+9)
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
def fetch(stock_number, year, month):
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
    return 'Success!'

def calculate_daily_return_rate(stock_number):
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

def calculate_sharpe_value(stock_number):
    if type(stock_number) != str:
        raise TypeError('Stock number is invalid.')
    if (stock_number in twstock.twse) == False:
        raise ValueError('Stock number is invalid.')
    result = calculate_daily_return_rate(stock_number)
    return float(round(result.mean()/result.std(), 4))

def calculate_william_value(stock_number):
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

def get_month_revenue(company_id, year, month):
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


if __name__ == "__main__":
    db.create_all()
    app.run()