FROM python:3.8-alpine

RUN addgroup app && adduser -s /bin/false -G app -D app

RUN mkdir /app
ADD code /app

USER app

ENTRYPOINT ["python"]
CMD ["/app/main.py"]
