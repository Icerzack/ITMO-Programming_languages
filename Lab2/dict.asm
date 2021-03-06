global find_word				;Объявляем find_word глобальным, чтобы другие файлы могли сделать extern find_word (в частности main.asm)

extern string_equals				;Берем string_equals из файла lib.asm

section .text					;Секция с кодом

						;В rdi находится указатель на нуль-терминированную строку
						;В rsi находится указатель на начало словаря
						;Возвращает адрес начала вхождения в словарь (не значения), иначе вернёт 0
find_word: 					;Начало кода 
    .find_word_loop:				;Локальная метка , тут происходит поиск совпадения по словарю
	test rsi, rsi				;Сравниваем rsi с 0 (0 означает, что это конец, дальше элементов нет)
	je .failed				;Если дальше элементов нет, а мы уже все просмотрели, то mission failed we'll get them next time, переходим к завершению программы
	push rdi				;Сохраняем на стеке указатель на нуль-терминированную строку
	push rsi				;Сохраняем на стеке указатель на след элемент
	add rsi, 8				;Перемещаем указатель (то есть rsi) на адрес ключа (прибавляем 8 потому что dq = 8)
	call string_equals			;Смотрим, равны ли строки в rdi и rsi?
	pop rsi					;Стягиваем со стека обратно наш адрес на след элемент
	pop rdi					;Стягиваем со стека обратно наш указатель на нуль-терминированную строку
	test rax, rax				;Неравны ли наши строки, rax == 0?
	jne .match				;Если равны, то it's a match!, переходим к завершению поиска 
	mov rsi, [rsi]				;Иначе же, если неравны, теперь заместо указателя на текущий рассматриваемый элемент кладем указатель на следующий
	jmp .find_word_loop			;Ну и опять идем по циклу поиска
    .match:					;Метка для найденного совпадения
	mov rax, rsi				;Тогда, если нашлось совпадение, то возвращаем найденный адрес вхождения
	ret					;Ну и выходим из подпрограммы
    .failed:					;Метка если совпадения не нашлось
	xor rax, rax				;Если по ходу ничего не нашли, то возвращаем 0
	ret     				;Ну и выходим из подпрограммы
