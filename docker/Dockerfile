
FROM python:slim
RUN mkdir -p /app/templates
WORKDIR /app
COPY ./src/requirements.txt /app/
RUN pip install -r requirements.txt
COPY ./src/kiss.py /app/
COPY ./src/templates /app/templates
CMD ["python", "kiss.py"]