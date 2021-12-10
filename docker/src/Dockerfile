
FROM python:slim
RUN mkdir /app
WORKDIR /app
COPY ./src/requirements.txt /app/
RUN pip install -r requirements.txt
COPY ./src/kiss.py /app/
CMD ["python", "kiss.py"]