"""
Hackathon Relâmpago - Caçadores de Fraudes
Autores: José Luis Moreira Cavalcante, Hideki Kozuma
Data: 06/04/2025
Objetivo: Detectar fraudes em lista de compras públicas utilizando Python.
"""

import pandas as pd

compras = pd.read_csv("public_servant_purchases_new.csv")
compras.head()

def detectar_compras_duplicadas(compras):
    # Filtrar registros duplicados com base no nome e no item
    duplicadas = compras[compras.duplicated(subset=["item_comprado", "nome_do_funcionario"], keep=False)].copy()
    
    # Adicionar uma coluna com a quantidade de duplicados
    duplicadas['quantidade_duplicada'] = duplicadas.groupby(["item_comprado", "nome_do_funcionario"])["item_comprado"].transform('count')
    
    return duplicadas

def verificar_valores_suspeitos(compras):
    # Verificar compras de alto valor
    compras_valor_alto = compras[compras['valor_em_real'] > 1000]

    # Filtrar registros com nomes não convencionais utilizando regex
    compras_nomes_irregulares = compras[
        compras['nome_do_funcionario'].str.contains(r'[^A-Za-zÀ-ÿ\s.,]', na=False)
    ]

    # Combinar os dois filtros
    registros_suspeitos = pd.concat([compras_valor_alto, compras_nomes_irregulares]).drop_duplicates()

    return registros_suspeitos

def compras_fora_de_horario(compras):
    compras['data_da_compra'] = pd.to_datetime(compras['data_da_compra'])

    compras['hora_decimal'] = compras['data_da_compra'].dt.hour + compras['data_da_compra'].dt.minute / 60

    fora_horario = compras[(compras['hora_decimal'] < 8) | (compras['hora_decimal'] > 18)]

    return fora_horario

def organizar_por_servidor(compras):
    resumo_servidores = compras.groupby("nome_do_funcionario").agg(
        itens_comprados=("item_comprado", lambda x: list(x)),
        valor_total=("valor_em_real", "sum"),
        quantidade_compras=("item_comprado", "count")
    ).reset_index()

    # Converter o DataFrame em um dicionário
    servidor_dict = resumo_servidores.set_index("nome_do_funcionario").to_dict(orient="index")

    return servidor_dict


def gerar_relatorio(compras):
    # Obter os registros suspeitos
    compras_valor_alto = compras[compras['valor_em_real'] > 1000]
    compras_nomes_irregulares = compras[
        compras['nome_do_funcionario'].str.contains(r'[^A-Za-zÀ-ÿ\s.,]', na=False)
    ]
    registros_suspeitos = pd.concat([compras_valor_alto, compras_nomes_irregulares]).drop_duplicates()

    # Classificar severidade das infrações
    def classificar_severidade(row):
        if row['valor_em_real'] > 5000:
            return "Alta"
        elif row['valor_em_real'] > 1000:
            return "Média"
        elif row['nome_do_funcionario'] and pd.notnull(row['nome_do_funcionario']):
            if any(char in row['nome_do_funcionario'] for char in "0123456789@#$%^&*"):
                return "Baixa"
        return "Indefinida"

    registros_suspeitos['severidade'] = registros_suspeitos.apply(classificar_severidade, axis=1)

    # Agrupar dados para o relatório
    relatorio = registros_suspeitos.groupby("severidade").agg(
        quantidade_infracoes=("severidade", "size"),
    ).reset_index()

    return relatorio


if __name__ == "__main__":
    print("Iniciando detecção de fraudes...")
    # Chamar as funções aqui e imprimir relatório
    print(verificar_valores_suspeitos(compras))
    print(detectar_compras_duplicadas(compras))
    print(compras_fora_de_horario(compras))
    print(organizar_por_servidor(compras))
    print(gerar_relatorio(compras))
