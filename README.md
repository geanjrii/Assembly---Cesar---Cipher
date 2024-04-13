# Programa de Cifra de César

Este é um programa desenvolvido em linguagem assembly (MASM32) que implementa a Cifra de César. A Cifra de César é um método de criptografia em que cada letra de um texto é substituída por outra letra, um número fixo de posições à frente no alfabeto.

## Funcionalidades

O programa oferece as seguintes opções:

1. Criptografar: Permite criptografar um arquivo de entrada usando a Cifra de César.
2. Descriptografar: Permite descriptografar um arquivo de entrada criptografado usando a Cifra de César.
3. Criptoanálise: Realiza uma análise estatística para identificar a chave mais provável usada na criptografia do arquivo de entrada.
4. Sair: Encerra a execução do programa.

## Uso do programa

Ao iniciar o programa, o usuário será apresentado a um menu de opções. Ele poderá escolher a opção desejada digitando o número correspondente e pressionando Enter.

### Criptografar

Ao escolher a opção 1, o usuário será solicitado a fornecer o nome do arquivo de entrada, o nome do arquivo de saída e a chave de criptografia. A chave deve ser um número inteiro no intervalo de 1 a 20. O programa irá criptografar o conteúdo do arquivo de entrada usando a chave fornecida e salvar o resultado no arquivo de saída.

### Descriptografar

Ao escolher a opção 2, o usuário será solicitado a fornecer o nome do arquivo de entrada, o nome do arquivo de saída e a chave de descriptografia. O programa irá descriptografar o conteúdo do arquivo de entrada usando a chave fornecida e salvar o resultado no arquivo de saída.

### Criptoanálise

Ao escolher a opção 3, o usuário será solicitado a fornecer o nome do arquivo de entrada. O programa realizará uma análise estatística do texto criptografado para identificar a chave mais provável utilizada na criptografia. O resultado será exibido na tela, indicando a chave com a maior pontuação.

### Sair

Ao escolher a opção 4, o programa será encerrado.
