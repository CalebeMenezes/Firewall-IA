import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os
import numpy as np

FEATURE_COLUMNS = ['pkt_count', 'avg_pkt_len', 'bytes_sum', 'dst_ports_count']
HISTORY_PATH = "data/history_features.csv"

def apply_feedback(row, new_level):
    """
    Corrige manualmente o nível de um pacote/IP na base histórica.
    """
    try:
        df = pd.read_csv(HISTORY_PATH)
        # Atualiza o nível do IP específico
        df.loc[df['src'] == row['src'], 'level'] = new_level
        df.to_csv(HISTORY_PATH, index=False)
        return True
    except Exception as e:
        print(f"Erro ao aplicar feedback: {e}")
        return False

# ------------------- Funções de pré-processamento -------------------

def prepare_features(df):
    """Seleciona colunas numéricas, remove registros inválidos e duplicados."""
    if not all(col in df.columns for col in FEATURE_COLUMNS):
        raise ValueError(f"Dataset inválido. Esperado colunas: {FEATURE_COLUMNS}")
    
    df_clean = df[FEATURE_COLUMNS].copy()
    df_clean = df_clean.dropna()
    df_clean = df_clean.replace([float("inf"), float("-inf")], None).dropna()
    df_clean = df_clean.drop_duplicates()
    
    return df_clean

# ------------------- Treino e classificação -------------------

def train_model(df, model_path="data/models/ia_model.pkl"):
    """Treina a IA usando Isolation Forest e salva o modelo."""
    df_clean = prepare_features(df)
    if df_clean.empty:
        raise ValueError("Dataset vazio após limpeza. Não é possível treinar a IA.")

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    )

    model.fit(df_clean)

    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(model, model_path)
    print(f"✅ Modelo treinado e salvo em {model_path}")
    return model

def classify_packets(df, model):
    # Seleciona as features
    features = df[['pkt_count', 'avg_pkt_len', 'bytes_sum', 'dst_ports_count']]
    
    # Score de anomalia (-1 = anomalia, 1 = normal)
    preds = model.predict(features)
    
    # Score contínuo (quanto mais negativo, mais anômalo)
    scores = model.decision_function(features)
    
    # Criar coluna de nível usando np.where para alinhar corretamente
    import numpy as np
    levels = np.where(scores > 0.05, "Verde", np.where(scores > -0.05, "Amarelo", "Vermelho"))
    
    # Atribui ao DataFrame garantindo que índices batam
    df['level'] = pd.Series(levels, index=df.index)
    df['score'] = pd.Series(scores, index=df.index)
    
    return df

def load_model(model_path="data/models/ia_model.pkl"):
    """Carrega modelo já treinado."""
    if not os.path.exists(model_path):
        raise FileExistsError("Modelo não encontrado. Treine primeiro com train_model()")
    model = joblib.load(model_path)
    print(f"✅ Modelo carregado de {model_path}")
    return model

def load_features(file_path="data/features.csv"):
    """Carrega dataset de features a partir de CSV."""
    if not os.path.exists(file_path):
        raise FileExistsError(f"Arquivo {file_path} não encontrado!")
    df = pd.read_csv(file_path)
    return df

# ------------------- Estatísticas do modelo -------------------

def model_statistics(df, model):
    """Retorna estatísticas úteis do modelo para log ou dashboard."""
    classified = classify_packets(df.copy(), model)
    scores = classified['score']
    levels = classified['level']

    stats = {
        "mean_score": np.mean(scores),
        "std_score": np.std(scores),
        "count_verde": (levels == "Verde").sum(),
        "count_amarelo": (levels == "Amarelo").sum(),
        "count_vermelho": (levels == "Vermelho").sum()
    }

    return stats


if __name__ == "__main__":
    df = pd.read_csv("data/features.csv")  # precisa existir!
    model = train_model(df)
    classified_df = classify_packets(df, model)
    
    print(classified_df[['src', 'minute', 'pkt_count', 'level', 'score']].head())
