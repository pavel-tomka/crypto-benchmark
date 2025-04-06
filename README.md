# Инструмент для сравнительного анализа криптографических алгоритмов

Этот инструмент обеспечивает сравнение производительности между различными криптографическими алгоритмами: AES (симметричный), RSA (асимметричный) и ECC (асимметричный). Он измеряет и сравнивает время генерации ключа, скорость шифрования, скорость дешифрования и накладные расходы для каждого алгоритма, используя настраиваемый объем тестовых данных.

## Обзор

Скрипт бенчмаркинга тестирует следующие криптографические реализации:
- **AES-256-GCM**: симметричный алгоритм шифрования
- **RSA-2048**: асимметричный алгоритм шифрования с собственной реализацией
- **ECC-256 (SECP256R1)**: асимметричный алгоритм шифрования с реализацией, подобной ECIES

Для каждого алгоритма скрипт измеряет:
- время генерации ключа
- скорость шифрования
- скорость дешифрования
- размер шифротекста (издержки)

## Требования

- Python 3.6+
- cryptography
- tabulate

## Установка

1. Клонируйте этот репозиторий:
```bash
git clone https://github.com/pavel-tomka/crypto-benchmark.git
cd crypto-benchmark
```

2. Создайте виртуальную среду (рекомендуется):
```bash
python -m venv venv
source venv/bin/activate # В Windows: venv\Scripts\activate
```

3. Установка зависимостей:
```bash
pip install cryptography tabulate
```

## Использование

Запустите скрипт напрямую:

```bash
python main.py
```

По умолчанию скрипт использует 1 МБ случайных данных для тестирования. Вы можете изменить константу `TEST_DATA_SIZE` в скрипте, чтобы настроить объем тестовых данных.

## Пример вывода

Скрипт выводит отформатированную таблицу с результатами теста:

```
Тестирование на 1.0 MB данных...

Результаты тестирования:
+--------------+---------------+----------------+-------------------+--------------+----------------+------------+
|   Алгоритм   |      Тип      |  Размер ключа  |  Генерация ключа  |  Шифрование  |  Дешифрование  |  Нагрузка  |
+==============+===============+================+===================+==============+================+============+
|     AES      | Симметричный  |    256 бит     |      0.00 мс      |   4.05 мс    |    1.66 мс     | 1024.0 KB  |
+--------------+---------------+----------------+-------------------+--------------+----------------+------------+
| RSA (native) | Асимметричный |    2048 бит    |    5741.32 мс     |  904.39 мс   |  106176.27 мс  | 1056.7 KB  |
+--------------+---------------+----------------+-------------------+--------------+----------------+------------+
| ECC (native) | Асимметричный |    256 бит     |      0.22 мс      |  4570.97 мс  |   4293.97 мс   | 3104.0 KB  |
+--------------+---------------+----------------+-------------------+--------------+----------------+------------+
```

## Как это работает

1. **Тест AES**: Тестирует AES-256-GCM со случайно сгенерированными 256-битными ключами
2. **Тест RSA**: Реализует собственный RSA-2048 с пользовательской генерацией простых чисел и проверкой простоты Миллера-Рабина
3. **Тест ECC**: Реализует схему, похожую на ECIES, с использованием кривой SECP256R1 (256 бит)

Для каждого алгоритма скрипт:
- Измеряет время генерации ключа
- Шифрует фиксированный объем случайных данных
- Измеряет время шифрования
- Расшифровывает зашифрованные данные
- Измеряет время расшифровки
- Рассчитывает размер шифротекста

## Примечания

- Реализации RSA и ECC предназначены для образовательных целей и сравнительного анализа
- Для больших объемов данных скрипт использует выборку и экстраполяцию для оценки производительности
- Скрипт использует библиотеку `cryptography` для AES и некоторых операций ECC, реализуя собственные версии шифрования RSA и ECC
- Производительность может меняться в зависимости от оборудования и нагрузки системы

## Лицензия

[Лицензия MIT](LICENSE)
