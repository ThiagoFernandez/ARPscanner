import auxiliar
import scanner


def main():
    options = ["scan", "compare results", "watch"]
    auxiliar.show_options(options)
    resultado = auxiliar.validate_number(options)
    if resultado == -1:
        return

    match resultado:
        case 1:
            scanner.start_scanner()
        case 2:
            scanner.compare_json()
        case 3:
            # scanner.watch()
            pass


main()
print("Finalizo el programa")
