
import joblib
import pandas as pd

from ucimlrepo import fetch_ucirepo
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)

from url_features import extract_url_features, FEATURE_NAMES


print("Downloading the UCI phishing URL dataset...")

dataset = fetch_ucirepo(id=967)

features_data = dataset.data.features
targets_data = dataset.data.targets

url_column = next(
    (
        column
        for column in features_data.columns
        if column.strip().lower() == "url"
    ),
    None,
)

if url_column is None:
    raise ValueError(
        "The dataset does not contain the expected URL column."
    )

if targets_data.shape[1] != 1:
    raise ValueError(
        "Unexpected target format. Inspect the dataset target columns."
    )

target_column = targets_data.columns[0]

data = pd.DataFrame({
    "url": features_data[url_column].astype("string"),
    "original_label": pd.to_numeric(
        targets_data[target_column],
        errors="coerce",
    ),
})

data = data.dropna()
data = data[data["original_label"].isin([0, 1])].copy()
data["url"] = data["url"].str.strip()
data = data[data["url"] != ""]

data["label"] = (data["original_label"] == 0).astype(int)

label_counts = data.groupby("url")["label"].nunique()
unambiguous_urls = label_counts[label_counts == 1].index
data = data[data["url"].isin(unambiguous_urls)]
data = data.drop_duplicates(subset=["url"]).reset_index(drop=True)

if data["label"].nunique() != 2:
    raise ValueError("Training data must contain both classes.")

print(f"Usable unique URLs: {len(data):,}")
print("Class distribution:")
print(data["label"].map({
    0: "Legitimate",
    1: "Phishing",
}).value_counts())

print("Extracting URL features...")

X = pd.DataFrame(
    [
        extract_url_features(url)
        for url in data["url"]
    ],
    columns=FEATURE_NAMES,
)

y = data["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

print("Training the Random Forest classifier...")

model = RandomForestClassifier(
    n_estimators=200,
    min_samples_leaf=2,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1,
)

model.fit(X_train, y_train)

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)
precision = precision_score(
    y_test,
    predictions,
    pos_label=1,
    zero_division=0,
)
recall = recall_score(
    y_test,
    predictions,
    pos_label=1,
    zero_division=0,
)
f1 = f1_score(
    y_test,
    predictions,
    pos_label=1,
    zero_division=0,
)

matrix = confusion_matrix(
    y_test,
    predictions,
    labels=[0, 1],
)

tn, fp, fn, tp = matrix.ravel()

false_positive_rate = (
    fp / (fp + tn)
    if (fp + tn) > 0
    else 0.0
)

print("\n===== MODEL EVALUATION =====")
print(f"Accuracy:            {accuracy:.4f}")
print(f"Phishing precision:  {precision:.4f}")
print(f"Phishing recall:     {recall:.4f}")
print(f"Phishing F1-score:   {f1:.4f}")
print(f"False positive rate: {false_positive_rate:.4f}")

print("\nConfusion matrix:")
print("Rows = actual; columns = predicted")
print("Order: Legitimate, Phishing")
print(matrix)

print("\nDetailed classification report:")
print(
    classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Legitimate", "Phishing"],
        zero_division=0,
    )
)

joblib.dump(
    {
        "model": model,
        "feature_names": FEATURE_NAMES,
    },
    "phishing_url_model.joblib",
)

print("\nModel saved as phishing_url_model.joblib")
