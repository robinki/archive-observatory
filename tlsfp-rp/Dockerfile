FROM pandas/pandas:alpine

WORKDIR /usr/src/tlsfp

RUN apk update && apk add git

COPY . .

RUN pip install -r requirements.txt

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

ENTRYPOINT ["./entrypoint.sh"]
