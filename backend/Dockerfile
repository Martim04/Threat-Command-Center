# Usar imagem oficial estável e leve do Python
FROM python:3.10-slim

# Definir variáveis de ambiente para otimização do Python
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Definir diretório de trabalho no contentor
WORKDIR /app

# Instalar dependências essenciais do sistema operativo (compiladores se necessário)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copiar apenas os requisitos para aproveitar o cache de camadas do Docker
COPY requirements.txt .

# Instalar as dependências do Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar os restantes ficheiros do backend
COPY . .

# Expor a porta em que a API FastAPI estará à escuta
EXPOSE 8000

# Comando para iniciar o servidor web Uvicorn (escutando em todas as interfaces)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
