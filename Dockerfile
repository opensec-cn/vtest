FROM python:2.7

ENV TZ=Asia/Shanghai

RUN set -ex
ENV DOMAIN vultest.com
ENV LOCALIP 127.0.0.1
# RUN apt-get update

ADD requirements.txt /tmp/requirements.txt
ADD vtest.py /app/vtest.py

RUN pip install -r /tmp/requirements.txt
RUN export PASSWORD=$(python2 -c "import random,string;print(''.join([random.choice(string.ascii_letters) for _ in range(32)]).encode());")

CMD ["sh", "-c", "echo $DOMAIN $LOCALIP $PASSWORD && /usr/local/bin/python2 /app/vtest.py -d $DOMAIN -h $LOCALIP -p $PASSWORD"]
