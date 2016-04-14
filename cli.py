#!/usr/bin/env python3

import readline

CURRENT_CONFIG_INTERFACE = None
CURRENT_MENU = ('null', 'null', [])
NAME = 'coreswitch'

def __menu__main__interface(param):
    global CURRENT_CONFIG_INTERFACE
    if param.strip().isnumeric():
        CURRENT_CONFIG_INTERFACE = int(param)
        set_menu('inter', '$name$-int-' + str(CURRENT_CONFIG_INTERFACE) + '>')
    else:
        print("Usage is interface <num>.")

def __menu__inter__tdr(_):
    print("Running TDR on " + str(CURRENT_CONFIG_INTERFACE))

def __menu__main__exit(_):
    quit()

def __menu__inter__exit(_):
    set_menu('main', '$name$> ')

def get_possible_completions(menu, enteredcmd):
    candidates = []
    menu = menu[2]

    cmd = enteredcmd.strip().split(' ')[0]

    for i in menu:
        if i == cmd:
            return [cmd]

        if i.startswith(cmd):
            candidates.append(i)

    return candidates


def readline_menu_completer(text, state):
    candidates = get_possible_completions(CURRENT_MENU, text)
    return candidates[state] if state < len(candidates) else None


readline.parse_and_bind("tab: complete")
readline.parse_and_bind("?: complete")
readline.set_completer(readline_menu_completer)

def run_command(menu, cmd):
    candidates = get_possible_completions(menu, cmd)

    if len(candidates) == 0:
        print('No such command.')
    elif len(candidates) > 1:
        print('Possible commands:\n' + ', '.join(candidates))
    else:
        function = globals().get('__menu__' + CURRENT_MENU[0] + "__" + candidates[0], None)
        if function != None:
            params = cmd.partition(' ')[2]
            function(params)
        else:
            print('Not implemented.')


def set_menu(menu, prompt=None):
    global CURRENT_MENU
    prompt = prompt if prompt != None else menu

    entries = []

    for i in globals().keys():
        if i.startswith('__menu__' + menu + '__'):
            entries.append(i[10 + len(menu):])

    CURRENT_MENU = (menu, prompt, entries)

def ps0():
    return CURRENT_MENU[1].replace('$name$', NAME)

def main():
    set_menu('main', '$name$> ')

    while True:
        command = ''

        while command.strip() == '':
            command = input(ps0())

        run_command(CURRENT_MENU, command)


if __name__ == "__main__":
    main()
