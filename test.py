import difflib

case_a = 'afrykbnersdfskojęzyczny'
case_b = 'afrykanerskojęzycznym'

output_list = [li for li in difflib.ndiff(case_a, case_b) if li[0] != ' ']

resultat = ''.join(x[2:] for x in output_list if x.startswith('+ '))

print(resultat)