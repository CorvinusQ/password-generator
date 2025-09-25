import secrets
import string

def generate_password(
    length: int = 12,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False
) -> str:
    """
    Генерирует надёжный пароль заданной длины и состава.

    :param length: Длина пароля (по умолчанию 12)
    :param use_uppercase: Использовать заглавные буквы
    :param use_lowercase: Использовать строчные буквы
    :param use_digits: Использовать цифры
    :param use_symbols: Использовать специальные символы
    :param exclude_ambiguous: Исключать неоднозначные символы (l, 1, O, 0 и т.д.)
    :return: Сгенерированный пароль
    """
    if length <= 0:
        raise ValueError("Длина пароля должна быть положительной.")

    # Базовые наборы символов
    chars = ""
    if use_lowercase:
        chars += string.ascii_lowercase
    if use_uppercase:
        chars += string.ascii_uppercase
    if use_digits:
        chars += string.digits
    if use_symbols:
        chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"

    if exclude_ambiguous:
        ambiguous = "l1I0O"
        chars = ''.join(c for c in chars if c not in ambiguous)

    if not chars:
        raise ValueError("Набор символов пуст. Проверьте параметры.")

    # Гарантируем наличие хотя бы одного символа из каждого выбранного класса
    password = []
    if use_lowercase:
        password.append(secrets.choice(string.ascii_lowercase))
    if use_uppercase:
        password.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        password.append(secrets.choice(string.digits))
    if use_symbols:
        password.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))

    # Дополняем до нужной длины
    if len(password) > length:
        raise ValueError("Слишком много обязательных классов символов для такой длины.")

    remaining_length = length - len(password)
    password += [secrets.choice(chars) for _ in range(remaining_length)]

    # Перемешиваем, чтобы избежать предсказуемого порядка
    secrets.SystemRandom().shuffle(password)

    return ''.join(password)


# Пример использования
if __name__ == "__main__":
    pwd = generate_password(
        length=16,
        use_uppercase=True,
        use_lowercase=True,
        use_digits=True,
        use_symbols=True,
        exclude_ambiguous=True
    )
    print("Сгенерированный пароль:", pwd)
