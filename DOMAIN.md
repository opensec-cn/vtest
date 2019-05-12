## 域名购买(只需一个域名即可)
https://sg.godaddy.com/

假设购买域名为: example.com

1. 添加A记录，子域名为ns，解析vps ip为 1.2.3.4
2. 添加NS记录，子域名为i，解析值为 ns.example.com
3. 再设置一个A记录，子域名为login，解析vps ip为 1.2.3.4

运行脚本: python vtest.py -d i.example.com -h 1.2.3.4 -p admin333

最终:

后台域名为: login.example.com

接收消息域名为: xxxx.i.example.com
