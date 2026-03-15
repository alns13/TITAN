import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

# Use absolute paths relative to this script's location
base_dir = os.path.dirname(os.path.abspath(__file__))
data_path = os.path.join(base_dir, '../data/raw/train.csv') 
output_path = os.path.join(base_dir, '../eda_distribution.png')

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

def run_eda():
    print("TITAN: Loading dataset")
    df = pd.read_csv(data_path, names=columns)

    # 3. Simplify Labels: "normal" vs "malicious"
    # We create a new column called 'binary_target'
    df['binary_target'] = df['attack_type'].apply(lambda x: 'normal' if x == 'normal' else 'malicious')

    # 4. Visualization
    plt.figure(figsize=(10, 6))
    sns.countplot(x='binary_target', data=df, palette='viridis')
    plt.title('TITAN: Normal vs. Malicious Traffic Distribution')
    plt.xlabel('Traffic Type')
    plt.ylabel('Packet Count')
    
    print(f" Saving distribution chart to: {output_path}")
    plt.savefig(output_path)
    
    # Print the raw numbers for the README
    print("\n--- Raw Stats ---")
    print(df['binary_target'].value_counts())

if __name__ == "__main__":
    run_eda()