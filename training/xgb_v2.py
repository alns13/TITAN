import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os

base_dir = os.path.dirname(os.path.abspath(__file__))
processed_data_path = os.path.join(base_dir, '../data/processed/train_cleaned.csv')

print("TITAN: Loading the universal cleaned dataset...")
df = pd.read_csv(processed_data_path)

print("TITAN: Slicing the 8-Feature subset...")
#get the 5 exact numerical features 
base_features = ['duration', 'src_bytes', 'count', 'srv_count', 'serror_rate']

#get the prefixes for the 3 categorical features that were one hot encoded
categorical_prefixes = ('protocol_type_', 'service_', 'flag_')

#separate the key feature
columns_to_keep = ['target'] 
for col in df.columns:
    if col in base_features or col.startswith(categorical_prefixes):
        columns_to_keep.append(col)

#slice the dataframe
df_titan = df[columns_to_keep]

#save column OHE structure for API
feature_cols = df_titan.drop('target', axis=1).columns.tolist()
joblib.dump(feature_cols, '../models/titan_columns.pkl')

print(f"Dataset sliced from {len(df.columns)} down to {len(feature_cols) + 1} features.")

#split data
X = df_titan.drop('target', axis=1)
y = df_titan['target']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = xgb.XGBClassifier(
    n_estimators=100, 
    learning_rate=0.1, 
    max_depth=5, 
    random_state=42
)
model.fit(X_train, y_train)

predictions = model.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, predictions) * 100:.2f}%")
print(classification_report(y_test, predictions))

#export model using pkl file
model.save_model("../models/titan_xgboost_v2.json")