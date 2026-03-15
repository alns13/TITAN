import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
import os

# Paths
base_dir = os.path.dirname(os.path.abspath(__file__))
raw_data_path = os.path.join(base_dir, '../data/raw/train.csv')
processed_data_path = os.path.join(base_dir, '../data/processed/train_cleaned.csv')

# Ensure the processed folder exists
os.makedirs(os.path.join(base_dir, '../data/processed'), exist_ok=True)

columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'attack_type', 'difficulty_level'
]

def preprocess_data():
    print("TITAN: Starting Preprocessing...")
    df = pd.read_csv(raw_data_path, names=columns)
    df.drop('difficulty_level', axis=1, inplace=True)

    #Binary Target Mapping
    df['target'] = df['attack_type'].apply(lambda x: 0 if x == 'normal' else 1)
    df.drop('attack_type', axis=1, inplace=True)

    #turns 'tcp', 'udp', etc. into columns of 0s and 1s
    df = pd.get_dummies(df, columns=['protocol_type', 'service', 'flag'])

    #Feature Scaling
    scaler = StandardScaler()
    feature_cols = df.columns.drop('target')
    df[feature_cols] = scaler.fit_transform(df[feature_cols])

    #Save the cleaned data
    df.to_csv(processed_data_path, index=False)
    print(f"Success. Cleaned data saved to: {processed_data_path}")
    print(f"Total features after encoding: {len(df.columns)}")

if __name__ == "__main__":
    preprocess_data()