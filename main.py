import argparse
import secrets
import string
import sys

def generate_password(
    length: int = 12,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False
) -> str:
    if length <= 0:
        raise ValueError("Длина пароля должна быть положительной.")

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

    # Обязательные символы из каждого включённого класса
    password = []
    if use_lowercase:
        password.append(secrets.choice(string.ascii_lowercase))
    if use_uppercase:
        password.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        password.append(secrets.choice(string.digits))
    if use_symbols:
        password.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))

    if len(password) > length:
        raise ValueError(
            "Слишком много обязательных классов символов для указанной длины. "
            "Увеличьте длину или отключите некоторые классы."
        )

    # Дозаполняем случайными символами
    remaining = length - len(password)
    password += [secrets.choice(chars) for _ in range(remaining)]

    # Перемешиваем
    secrets.SystemRandom().shuffle(password)
    return ''.join(password)


def main():
    parser = argparse.ArgumentParser(
        description="🔐 Надёжный генератор паролей на Python",
        epilog="Пример: python password_gen.py -l 16 --no-symbols --exclude-ambiguous"
    )

    parser.add_argument(
        '-l', '--length',
        type=int,
        default=12,
        help='Длина пароля (по умолчанию: 12)'
    )

    parser.add_argument(
        '--no-uppercase',
        action='store_true',
        help='Не использовать заглавные буквы'
    )

    parser.add_argument(
        '--no-lowercase',
        action='store_true',
        help='Не использовать строчные буквы'
    )

    parser.add_argument(
        '--no-digits',
        action='store_true',
        help='Не использовать цифры'
    )

    parser.add_argument(
        '--no-symbols',
        action='store_true',
        help='Не использовать специальные символы'
    )

    parser.add_argument(
        '--exclude-ambiguous',
        action='store_true',
        help='Исключить неоднозначные символы (l, 1, I, 0, O)'
    )

    parser.add_argument(
        '--count',
        type=int,
        default=1,
        help='Сколько паролей сгенерировать (по умолчанию: 1)'
    )

    args = parser.parse_args()

    # Валидация: хотя бы один тип символов должен быть включён
    if (args.no_uppercase and args.no_lowercase and args.no_digits and args.no_symbols):
        parser.error("Должен быть включён хотя бы один тип символов!")

    if args.count < 1:
        parser.error("Количество паролей должно быть >= 1")

    # Генерация
    for _ in range(args.count):
        try:
            pwd = generate_password(
                length=args.length,
                use_uppercase=not args.no_uppercase,
                use_lowercase=not args.no_lowercase,
                use_digits=not args.no_digits,
                use_symbols=not args.no_symbols,
                exclude_ambiguous=args.exclude_ambiguous
            )
            print(pwd)
        except ValueError as e:
            print(f"Ошибка: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
