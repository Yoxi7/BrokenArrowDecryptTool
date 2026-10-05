# Расшифровать
./broken-arrow-dek decrypt deck.dek deck.json

# Зашифровать (случайный IV)
./broken-arrow-dek encrypt deck.json deck-modified.dek

# Зашифровать с конкретным IV (минимальный diff)
./broken-arrow-dek encrypt deck.json deck-modified.dek --iv <32-hex>

# Компактный JSON
./broken-arrow-dek encrypt deck.json deck-modified.dek --compact