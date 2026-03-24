import os
import joblib
import pandas as pd
import xgboost as xgb
from xgboost import XGBClassifier 

FEATURES = ['duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
        'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
        'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 
        'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 
        'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 
        'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 
        'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 
        'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 
        'protocol_type_icmp', 'protocol_type_tcp', 'protocol_type_udp', 'service_IRC', 'service_X11', 
        'service_Z39_50', 'service_aol', 'service_auth', 'service_bgp', 'service_courier', 'service_csnet_ns', 
        'service_ctf', 'service_daytime', 'service_discard', 'service_domain', 'service_domain_u', 
        'service_echo', 'service_eco_i', 'service_ecr_i', 'service_efs', 'service_exec', 'service_finger', 
        'service_ftp', 'service_ftp_data', 'service_gopher', 'service_harvest', 'service_hostnames', 
        'service_http', 'service_http_2784', 'service_http_443', 'service_http_8001', 'service_imap4', 
        'service_iso_tsap', 'service_klogin', 'service_kshell', 'service_ldap', 'service_link', 
        'service_login', 'service_mtp', 'service_name', 'service_netbios_dgm', 'service_netbios_ns', 
        'service_netbios_ssn', 'service_netstat', 'service_nnsp', 'service_nntp', 'service_ntp_u', 
        'service_other', 'service_pm_dump', 'service_pop_2', 'service_pop_3', 'service_printer', 
        'service_private', 'service_red_i', 'service_remote_job', 'service_rje', 'service_shell', 
        'service_smtp', 'service_sql_net', 'service_ssh', 'service_sunrpc', 'service_supdup', 
        'service_systat', 'service_telnet', 'service_tftp_u', 'service_tim_i', 'service_time', 
        'service_urh_i', 'service_urp_i', 'service_uucp', 'service_uucp_path', 'service_vmnet', 
        'service_whois', 'flag_OTH', 'flag_REJ', 'flag_RSTO', 'flag_RSTOS0', 'flag_RSTR', 'flag_S0', 
        'flag_S1', 'flag_S2', 'flag_S3', 'flag_SF', 'flag_SH'
        ]

def load_resources():
    #get absolute path of inference.py
    src = os.path.dirname(__file__)
    project_root = os.path.dirname(src)

    #join abs_path with the TITAN dir
    scaler_path = os.path.join(project_root, 'models/data_scaler.pkl')
    titan_path = os.path.join(project_root, 'models/titan_xgb_v1.pkl')
    
    #load resources
    loaded_scaler = joblib.load(scaler_path)
    loaded_titan = joblib.load(titan_path)
    
    return loaded_titan, loaded_scaler


def predict_packet(raw_data, loaded_titan, loaded_scaler):  
    #first check if any values are strings
    is_raw_data = any(isinstance(val, str) for val in raw_data.values())
    
    # Check if keys are one hot encoded
    is_encoded = any(key.startswith('protocol_type_') for key in raw_data.keys())

    #if data is already scaled and encoded
    if not is_raw_data and is_encoded:
        #wrap it in df, align columns, and remove target feature
        df = pd.DataFrame([raw_data])
        if 'target' in df.columns:
            df = df.drop('target', axis=1)
            
        expected_order = loaded_titan.get_booster().feature_names
        final_df = df[expected_order].astype('float32')
        
        prediction = loaded_titan.predict_proba(final_df)

    #otherwise scale, 1HE, and map key val pairs
    else:
        #init all values to be 0
        df = pd.DataFrame(columns=FEATURES)
        df.loc[0] = 0.0

        for key, value in raw_data.items():
            #if value is an int and key exists in FEATURES, overwrite value for that key
            if isinstance(value, (int,float)) and key in FEATURES:
                df.at[0,key] = value

            else:
                #if value is string, change key name with fstring
                new_key_name = f"{key}_{value}"

                #one hot encode: if new key name is in FEATURES, give it a val of 1
                if new_key_name in FEATURES:
                    df.at[0,new_key_name] = 1
        
        df=df.astype('float32')

        #maintain feature order
        expected_order = loaded_titan.get_booster().feature_names
        df = df[expected_order]

        #scale data
        scaled_row = loaded_scaler.transform(df)
        final_df = pd.DataFrame(scaled_row, columns=expected_order)
        prediction = loaded_titan.predict_proba(final_df)

    return float(prediction[0][1])

if __name__ == "__main__":
    import sys
    import json
    
    try:
        titan_model, data_scaler = load_resources()
    except Exception as e:
        #if the model fails to load, output a JSON error
        print(json.dumps({"status": "error", "message": f"Failed to load TITAN: {str(e)}"}))
        sys.exit(1)

    #check for incoming data
    if len(sys.argv) > 1:
        raw_input = sys.argv[1]
        
        try:
            #parse incoming JSON string into a python dict
            live_packet = json.loads(raw_input)
            
            #run prediction pipeline
            alert_level = predict_packet(live_packet, titan_model, data_scaler)
            
            #construct alert payload
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
        #output if script is run directly without data
        print("TITAN IDS ONLINE. Usage: python inference.py '<json_packet_string>'")
            


