from flask import Flask, render_template, request
from crawler import run_crawler
from preprocessing import run_preprocessing
from model_predict import run_model

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    logs = []

    # Step 1: Crawler
    crawled_data = run_crawler(url)
    logs.append("Reached crawler")

    # Step 2: Preprocessing
    preprocessed = run_preprocessing(crawled_data)
    logs.append("Reached preprocessing")

    # Step 3: Model
    model_result = run_model(preprocessed)
    logs.append("Reached model")

    # Append model results
    logs.extend(model_result)

    return render_template('index.html', steps=logs, url=url)

if __name__ == '__main__':
    app.run(debug=True)
