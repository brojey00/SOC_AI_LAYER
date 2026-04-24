import pandas as pd
import pickle

# Load your scaler and columns once at the start
with open('label_encoder.pkl', 'rb') as f:
    scaler = pickle.load(f)
with open('feature_columns.pkl', 'rb') as f:
    model_columns = pickle.load(f)


def clean_flow_data(raw_dict):
    # 1. Convert dict to DataFrame
    df = pd.DataFrame([raw_dict])

    # 2. Select only the columns your model was trained on
    # (Matches the order and names in feature_columns.pkl)
    df = df.reindex(columns=model_columns, fill_value=0)

    # 3. Handle missing values/infinity (common in network traffic)
    df.replace([float('inf'), float('-inf')], 0, inplace=True)
    df.fillna(0, inplace=True)

    # 4. Scale the data
    scaled_data = scaler.transform(df)
    return scaled_data