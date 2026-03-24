import os
import sys
import json
import joblib
import pandas as pd
import xgboost as xgb

def load_resources():
    #get absolute path of inference.py
    src = os.path.dirname(__file__)
    project_root = os.path.dirname(src)

    scaler_path = os.path.join(project_root, 'models/data_scaler.pkl')
    columns_path = os.path.join(project_root, 'models/titan_columns.pkl')
    titan_path = os.path.join(project_root, 'models/titan_xgboost_v2.json')
    
    loaded_scaler = joblib.load(scaler_path)
    titan_columns = joblib.load(columns_path)
    
    loaded_titan = xgb.XGBClassifier()
    loaded_titan.load_model(titan_path)
    
    return loaded_titan, loaded_scaler, titan_columns

def predict_packet(raw_data, loaded_titan, loaded_scaler, titan_columns):  
    
    scaler_cols = loaded_scaler.feature_names_in_
    df_scaler = pd.DataFrame(columns=scaler_cols)
    df_scaler.loc[0] = 0.0

    for key, value in raw_data.items():
        if isinstance(value, (int, float)) and key in scaler_cols:
            df_scaler.at[0, key] = value

    scaled_array = loaded_scaler.transform(df_scaler)
    df_scaled = pd.DataFrame(scaled_array, columns=scaler_cols)

    df_final = pd.DataFrame(columns=titan_columns)
    df_final.loc[0] = 0.0

    for key, value in raw_data.items():
        if isinstance(value, (int, float)) and key in titan_columns:
            df_final.at[0, key] = df_scaled.at[0, key]

        elif isinstance(value, str):
            new_key_name = f"{key}_{value}"
            if new_key_name in titan_columns:
                df_final.at[0, new_key_name] = 1
    
    df_final = df_final[titan_columns].astype('float32')

    #make prediction
    prediction = loaded_titan.predict_proba(df_final)
    return float(prediction[0][1])

if __name__ == "__main__":
    try:
        titan_model, data_scaler, titan_blueprint = load_resources()
    except Exception as e:
        print(json.dumps({"status": "error", "message": f"Failed to load TITAN: {str(e)}"}))
        sys.exit(1)

    if len(sys.argv) > 1:
        raw_input = sys.argv[1]
        
        try:
            live_packet = json.loads(raw_input)
            alert_level = predict_packet(live_packet, titan_model, data_scaler, titan_blueprint)
            result = {
                "status": "success",
                "attack_probability": round(alert_level, 4),
                "is_threat": bool(alert_level > 0.80) 
            }
            
            print(json.dumps(result))
            
        except json.JSONDecodeError:
            print(json.dumps({"status": "error", "message": "Invalid JSON format provided."}))
            sys.exit(1)
        except Exception as e:
            print(json.dumps({"status": "error", "message": f"Prediction pipeline failed: {str(e)}"}))
            sys.exit(1)
    else:
        print("TITAN IDS ONLINE. Usage: python inference.py '<json_packet_string>'")