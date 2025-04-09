from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os
import timeit
import random
import math
from tabulate import tabulate

# Размер тестовых данных: 1 МБ
TEST_DATA_SIZE = 1 * 1024 * 1024
# Количество повторений для измерения скорости
ITERATIONS = 5
# Создаем случайные данные для тестирования
DATA = os.urandom(TEST_DATA_SIZE)

def test_aes():
    """Тестирование симметричного алгоритма AES-256 в режиме GCM"""
    # Генерируем случайный ключ размером 32 байта (256 бит)
    key = os.urandom(32)

    # Измеряем время генерации ключей
    key_gen_time = timeit.timeit(
        lambda: os.urandom(32),
        number=ITERATIONS
    ) / ITERATIONS

    # Шифрование данных с AES-256-GCM
    # Замеряем время шифрования
    encrypt_time = 0
    for _ in range(ITERATIONS):
        start_time = timeit.default_timer()

        # Создаем случайный nonce для режима GCM (12 байт)
        nonce = os.urandom(12)
        # Инициализируем шифр
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        # Шифруем данные и получаем тег аутентификации
        ciphertext = encryptor.update(DATA) + encryptor.finalize()
        tag = encryptor.tag

        encrypt_time += timeit.default_timer() - start_time

    encrypt_time /= ITERATIONS

    # Дешифрование данных
    # Замеряем время дешифрования
    decrypt_time = 0
    for _ in range(ITERATIONS):
        start_time = timeit.default_timer()

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        # Дешифруем данные
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        decrypt_time += timeit.default_timer() - start_time

    decrypt_time /= ITERATIONS

    # Формируем результат
    results = {
        "Тип": "Симметричный",
        "Размер ключа": "256 бит",
        "Генерация ключа": f"{key_gen_time * 1000:.2f} мс",
        "Шифрование": f"{encrypt_time * 1000:.2f} мс",
        "Дешифрование": f"{decrypt_time * 1000:.2f} мс",
        "Нагрузка": f"{len(ciphertext) / 1024:.1f} KB"
    }
    return results

def test_rsa_native():
    """Тестирование асимметричного алгоритма RSA с нативной реализацией"""

    # Проверка числа на простоту с использованием теста Миллера-Рабина
    def is_prime(n, k=5):
        # Базовые случаи
        if n <= 1 or n == 4:
            return False
        if n <= 3:
            return True

        # Находим r и d такие, что n-1 = 2^r * d, где d нечетное
        d = n - 1
        r = 0
        while d % 2 == 0:
            d //= 2
            r += 1

        # Проводим k тестов на простоту
        for _ in range(k):
            # Выбираем случайное число для теста
            a = random.randint(2, n - 2)
            # Вычисляем a^d mod n
            x = pow(a, d, n)

            # Проверяем условия теста Миллера-Рабина
            if x == 1 or x == n - 1:
                continue

            # Проверяем последовательные квадраты
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                # Если ни одно условие не выполнено, число составное
                return False

        # Если все тесты прошли, число вероятно простое
        return True

    # Наибольший общий делитель с использованием алгоритма Евклида
    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a

    # Нахождение мультипликативного обратного по модулю (расширенный алгоритм Евклида)
    def mod_inverse(e, phi):
        # Начальные значения
        a, b = e, phi
        x0, x1 = 1, 0
        y0, y1 = 0, 1

        # Пока второе число не станет нулем
        while b:
            # Целочисленное деление и остаток
            q, r = divmod(a, b)
            a, b = b, r
            x0, x1 = x1, x0 - q * x1
            y0, y1 = y1, y0 - q * y1

        # Проверка существования обратного
        if a != 1:
            raise Exception('Модульная инверсия не существует')

        # Приводим результат к положительному значению по модулю phi
        return (x0 % phi + phi) % phi

    # Генерирует простое число заданного размера в битах
    def generate_prime(bits):
        while True:
            # Генерируем случайное нечетное число нужной длины
            # Устанавливаем старший бит для гарантии нужной длины
            p = random.getrandbits(bits) | (1 << bits - 1) | 1
            if is_prime(p):
                return p

    # Замеряем время генерации ключей RSA
    start_time = timeit.default_timer()

    # Генерируем ключевую пару RSA длиной 2048 бит
    # Выбираем два простых числа p и q
    p = generate_prime(1024)  # Половина длины ключа
    q = generate_prime(1024)  # Половина длины ключа

    # Вычисляем модуль n = p * q
    n = p * q

    # Вычисляем функцию Эйлера phi(n) = (p-1)(q-1)
    phi = (p - 1) * (q - 1)

    # Выбираем открытую экспоненту e
    e = 65537  # Обычно используется число 65537, т.к. это простое и имеет малый вес Хэмминга
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    # Вычисляем закрытую экспоненту d
    d = mod_inverse(e, phi)

    # Формируем ключи: открытый (e, n) и закрытый (d, n)
    public_key = (e, n)
    private_key = (d, n)

    key_gen_time = timeit.default_timer() - start_time

    # Для ускорения тестирования используем только часть данных
    test_data = DATA[:10000]  # Берем первые 10KB данных

    # Замеряем время шифрования
    encrypt_time = 0
    for _ in range(ITERATIONS):
        start_time = timeit.default_timer()

        # Шифруем тестовые данные
        encrypted_data = bytearray()

        # Вычисляем размер блока для шифрования (байты)
        # Размер блока должен быть меньше размера модуля для избежания переполнения
        block_size = int((math.log(n, 256)) - 1)

        # Шифруем данные блоками
        for i in range(0, len(test_data), block_size):
            # Берем блок данных
            block = test_data[i:i + block_size]

            # Преобразуем блок в целое число
            m = int.from_bytes(block, byteorder='big')

            # Шифруем: c = m^e mod n
            c = pow(m, e, n)

            # Преобразуем шифртекст обратно в байты
            c_bytes = c.to_bytes((c.bit_length() + 7) // 8, byteorder='big')

            # Сохраняем длину зашифрованного блока для корректной расшифровки
            length_bytes = len(c_bytes).to_bytes(2, byteorder='big')
            encrypted_data.extend(length_bytes + c_bytes)

        encrypt_time += timeit.default_timer() - start_time

    encrypt_time /= ITERATIONS
    # Масштабируем результат для полного размера данных
    encrypt_time = encrypt_time * (len(DATA) / len(test_data))

    # Готовим шифртекст для тестирования дешифрования
    ciphertext = bytearray()
    for i in range(0, len(test_data), block_size):
        block = test_data[i:i + block_size]
        m = int.from_bytes(block, byteorder='big')
        c = pow(m, e, n)
        c_bytes = c.to_bytes((c.bit_length() + 7) // 8, byteorder='big')
        length_bytes = len(c_bytes).to_bytes(2, byteorder='big')
        ciphertext.extend(length_bytes + c_bytes)

    # Замеряем время дешифрования
    decrypt_time = 0
    for _ in range(ITERATIONS):
        start_time = timeit.default_timer()

        # Дешифруем данные
        decrypted_data = bytearray()
        i = 0

        # Читаем блоки данных
        while i < len(ciphertext):
            # Читаем длину текущего блока
            length = int.from_bytes(ciphertext[i:i + 2], byteorder='big')
            i += 2

            # Получаем шифртекст текущего блока
            c_bytes = ciphertext[i:i + length]
            i += length

            # Преобразуем в целое число
            c = int.from_bytes(c_bytes, byteorder='big')

            # Дешифруем: m = c^d mod n
            m = pow(c, d, n)

            # Преобразуем обратно в байты
            byte_length = (m.bit_length() + 7) // 8
            m_bytes = m.to_bytes(byte_length, byteorder='big')
            decrypted_data.extend(m_bytes)

        decrypt_time += timeit.default_timer() - start_time

    decrypt_time /= ITERATIONS
    # Масштабируем результат для полного размера данных
    decrypt_time = decrypt_time * (len(DATA) / len(test_data))

    # Оцениваем размер шифртекста для полного размера данных
    estimated_ciphertext_size = len(ciphertext) * (len(DATA) / len(test_data))

    # Формируем результат
    results = {
        "Тип": "Асимметричный",
        "Размер ключа": "2048 бит",
        "Генерация ключа": f"{key_gen_time * 1000:.2f} мс",
        "Шифрование": f"{encrypt_time * 1000:.2f} мс",
        "Дешифрование": f"{decrypt_time * 1000:.2f} мс",
        "Нагрузка": f"{estimated_ciphertext_size / 1024:.1f} KB"
    }
    return results

def test_pure_ecc():
    """Тестирование эллиптической криптографии (ECC) с размером ключа 256 бит"""

    # Генерируем кривую и ключевую пару
    curve = ec.SECP256R1()  # Используем стандартную кривую P-256 (256 бит)

    # Замеряем время генерации ключей
    key_gen_time = 0
    for _ in range(ITERATIONS):
        start_time = timeit.default_timer()
        # Генерируем приватный ключ
        private_key = ec.generate_private_key(curve, default_backend())
        key_gen_time += timeit.default_timer() - start_time

    key_gen_time /= ITERATIONS

    # Генерируем ключевую пару для тестов
    private_key = ec.generate_private_key(curve, default_backend())
    public_key = private_key.public_key()

    # Поскольку ECC не может напрямую шифровать большие объемы данных,
    # разбиваем данные на небольшие фрагменты
    chunk_size = 32  # 32 байта (256 бит) - максимум для кривой P-256
    chunks = [DATA[i:i + chunk_size] for i in range(0, len(DATA), chunk_size)]

    # Берем только первые 100 фрагментов для ускорения тестирования
    test_chunks = chunks[:100]

    # Замеряем время шифрования
    encrypt_time = 0
    encrypted_chunks = []

    for _ in range(ITERATIONS):
        start_time = timeit.default_timer()

        for chunk in test_chunks:
            # Реализация шифрования на ECC (упрощенная схема ECIES)

            # 1. Генерируем временную пару ключей
            temp_private = ec.generate_private_key(public_key.curve, default_backend())
            temp_public = temp_private.public_key()

            # 2. Обмен ключами по протоколу Диффи-Хеллмана
            shared_secret = temp_private.exchange(ec.ECDH(), public_key)

            # 3. Получаем симметричный ключ из общего секрета
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'ecies-encryption',
                backend=default_backend()
            )
            key = hkdf.derive(shared_secret)

            # 4. Шифруем данные с помощью XOR (в упрощенной версии)
            # В реальном ECIES используется полноценное симметричное шифрование
            ciphertext = bytes(a ^ b for a, b in zip(chunk, key[:len(chunk)]))

            # 5. Сохраняем временный публичный ключ для дешифрования
            pub_bytes = temp_public.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )

            # Формируем итоговый шифртекст (публичный ключ + шифрованные данные)
            encrypted_chunk = pub_bytes + ciphertext
            if _ == 0:
                encrypted_chunks.append(encrypted_chunk)

        encrypt_time += timeit.default_timer() - start_time

    encrypt_time /= ITERATIONS
    # Масштабируем результат на полный объем данных
    encrypt_time = encrypt_time * (len(chunks) / len(test_chunks))

    # Замеряем время дешифрования
    decrypt_time = 0

    for _ in range(ITERATIONS):
        start_time = timeit.default_timer()

        for encrypted_chunk in encrypted_chunks:
            # Получаем длину публичного ключа
            sample_pub = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            pub_len = len(sample_pub)

            # Извлекаем публичный ключ отправителя и шифртекст
            pub_key_bytes = encrypted_chunk[:pub_len]
            encrypted_data = encrypted_chunk[pub_len:]

            # Восстанавливаем временный публичный ключ
            temp_public = ec.EllipticCurvePublicKey.from_encoded_point(
                private_key.curve,
                pub_key_bytes
            )

            # Обмен ключами
            shared_secret = private_key.exchange(ec.ECDH(), temp_public)

            # Получаем симметричный ключ из общего секрета
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'ecies-encryption',
                backend=default_backend()
            )
            key = hkdf.derive(shared_secret)

            # Дешифруем данные с помощью XOR
            plaintext = bytes(a ^ b for a, b in zip(encrypted_data, key[:len(encrypted_data)]))

        decrypt_time += timeit.default_timer() - start_time

    decrypt_time /= ITERATIONS
    # Масштабируем результат на полный объем данных
    decrypt_time = decrypt_time * (len(chunks) / len(test_chunks))

    # Оцениваем общий размер шифртекста
    avg_chunk_size = sum(len(c) for c in encrypted_chunks) / len(encrypted_chunks)
    estimated_ciphertext_size = avg_chunk_size * len(chunks)

    # Формируем результат
    results = {
        "Тип": "Асимметричный",
        "Размер ключа": "256 бит",
        "Генерация ключа": f"{key_gen_time * 1000:.2f} мс",
        "Шифрование": f"{encrypt_time * 1000:.2f} мс",
        "Дешифрование": f"{decrypt_time * 1000:.2f} мс",
        "Нагрузка": f"{estimated_ciphertext_size / 1024:.1f} KB"
    }
    return results

# Главная функция программы
if __name__ == "__main__":
    print(f"Тестирование на {TEST_DATA_SIZE / 1024 / 1024:.1f} MB данных...")

    # Запускаем тесты для каждого алгоритма
    aes_results = test_aes()
    rsa_results = test_rsa_native()
    ecc_results = test_pure_ecc()

    # Объединяем результаты в словарь
    tests = {
        "AES": aes_results,
        "RSA (native)": rsa_results,
        "ECC (native)": ecc_results
    }

    # Подготавливаем заголовки таблицы
    headers = ["Алгоритм", "Тип", "Размер ключа", "Генерация ключа",
               "Шифрование", "Дешифрование", "Нагрузка"]

    # Формируем таблицу для вывода
    table = []
    for algo_name, results in tests.items():
        row = [algo_name]
        for header in headers[1:]:
            row.append(results[header])
        table.append(row)

    # Выводим результаты
    print("\nРезультаты тестирования:")
    print(tabulate(table, headers=headers, tablefmt="grid", stralign="center"))
