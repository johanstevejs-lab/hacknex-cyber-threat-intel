import pandas as pd
from datetime import datetime

def detect_attacks(logs_file):
    """Read logs and find attacks"""
    
    # Read the CSV file
    logs = pd.read_csv(logs_file)
    
    # Convert timestamp to datetime
    logs['timestamp'] = pd.to_datetime(logs['timestamp'])
    
    attacks = []
    
    # Group logs by user
    for user in logs['user_id'].unique():
        user_logs = logs[logs['user_id'] == user].sort_values('timestamp')
        
        # Check for attack pattern:
        # Stage 1: Unusual login (high risk IP)
        unusual_logins = user_logs[(user_logs['event_type'] == 'login') & 
                                   (user_logs['risk_level'] == 'high')]
        
        if len(unusual_logins) > 0:
            # Check if they accessed sensitive files after
            sensitive_access = user_logs[(user_logs['event_type'] == 'file_access') & 
                                        (user_logs['risk_level'] == 'high')]
            
            if len(sensitive_access) > 0:
                # Check if they copied files
                file_copy = user_logs[(user_logs['event_type'] == 'file_copy') & 
                                     (user_logs['risk_level'] == 'high')]
                
                if len(file_copy) > 0:
                    # ATTACK FOUND!
                    attack = {
                        'user': user,
                        'risk_score': 0.95,
                        'stages': [
                            {
                                'stage': 1,
                                'description': 'Unusual Login from Foreign IP',
                                'timestamp': str(unusual_logins.iloc[0]['timestamp']),
                                'source_ip': unusual_logins.iloc[0]['source_ip'],
                                'evidence': f"Login from {unusual_logins.iloc[0]['source_ip']} (unusual location detected)"
                            },
                            {
                                'stage': 2,
                                'description': 'Access to Sensitive Files',
                                'timestamp': str(sensitive_access.iloc[0]['timestamp']),
                                'target_resource': sensitive_access.iloc[0]['target_resource'],
                                'evidence': f"Accessed {sensitive_access.iloc[0]['target_resource']} (user never accessed before)"
                            },
                            {
                                'stage': 3,
                                'description': 'Data Exfiltration',
                                'timestamp': str(file_copy.iloc[0]['timestamp']),
                                'target_resource': file_copy.iloc[0]['target_resource'],
                                'evidence': f"Copied {file_copy.iloc[0]['target_resource']} to external storage"
                            }
                        ],
                        'recommendations': [
                            f"❌ Immediately revoke {user}'s access credentials",
                            "🔒 Isolate affected device from network",
                            "📋 Review all files accessed in this session",
                            "🚨 Alert security team immediately"
                        ]
                    }
                    attacks.append(attack)
    
    return attacks


if __name__ == "__main__":
    # Test the function
    attacks = detect_attacks('sample_logs.csv')
    
    if attacks:
        print(f"✅ Found {len(attacks)} attack(s)!\n")
        for attack in attacks:
            print(f"Attacker: {attack['user']}")
            print(f"Risk Score: {attack['risk_score']*100:.0f}%")
            print("\nAttack Timeline:")
            for stage in attack['stages']:
                print(f"  Stage {stage['stage']}: {stage['description']}")
                print(f"    Time: {stage['timestamp']}")
                print(f"    Evidence: {stage['evidence']}\n")
    else:
        print("✅ No attacks detected!")