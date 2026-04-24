import pickle

from process_flows import prepare_features


if __name__ == "__main__":
    with open("feature_columns.pkl", "rb") as f:
        columns = pickle.load(f)

    sample = {col: "0" for col in columns}
    frame = prepare_features(sample, columns)

    print(f"rows={frame.shape[0]} cols={frame.shape[1]}")
    print(frame.head(1).to_dict(orient="records")[0])

