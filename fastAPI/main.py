from fastapi import FastAPI, WebSocket
import pickle
from process_flows import clean_flow_data

app = FastAPI()

# Load model
with open('global_model.pkl', 'rb') as f:
    model = pickle.load(f)


@app.websocket("/ws/predict")
async def predict_stream(websocket: WebSocket):
    await websocket.accept()
    while True:
        # Receive the raw flow from the Watcher
        data = await websocket.receive_json()

        # Clean the data
        cleaned_data = clean_flow_data(data)

        # Predict
        prediction = model.predict(cleaned_data)[0]

        if prediction != "Normal":
            print(f"!!! ATTACK DETECTED: {prediction} !!!")
            # This is where you trigger the next step (Wazuh check)