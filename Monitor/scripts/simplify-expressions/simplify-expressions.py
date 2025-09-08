#given a set of Z3 expressions from KRover results, simplify in to a readable format
import re

# Define operation simplification rules
operation_rules = {
   'Ult': lambda args: f"({args[0]} < {args[1]})",
   'And': lambda args: f"({args[0]} and {args[1]})",
    'Or': lambda args: f"({args[0]} or {args[1]})",
   'Add': lambda args: f"({args[0]} + {args[1]})",
   'Mul': lambda args: f"({args[0]} x {args[1]})",
   'LShr': lambda args: f"({args[0]} >> {args[1]})",
   'Shl': lambda args: f"({args[0]} << {args[1]})",
   'LNot': lambda args: f"!({args[0]})",
   'ZeroEXT': lambda args: f"({args[0]})",
   #'ZeroEXT': lambda args: f"zero_extend({args[0]})",
   #for the moment we want to ignore the zero values being combined
   #'CombineMulti': lambda args: f"({args[0]})" if (args[1] == args[2] == args[3] == args[4] == "0x0") else ( f"concat({args[1], args[0]})" if len(args) == 2 else "CombineMulti-ERR"),
   'CombineMulti': lambda args: 
    # f"({args[0]})" if len(args) == 5 and (args[1] == args[2] == args[3] == args[4] == '0x0') else
    f"concat({args[1]}, {args[0]})" if len(args) == 2 else
    f"concat({args[4]}, {args[3]}, {args[2]}, {args[1]}, {args[0]})" if len(args) == 5 else
    "CombineMulti-ERR",
   'Ugt': lambda args: f"({args[0]} > {args[1]})",
   'Uge': lambda args: f"({args[0]} >= {args[1]})",
   'Sgt': lambda args: f"({args[0]} > {args[1]})",
   'Sle': lambda args: f"({args[0]} <= {args[1]})",
   'Sub': lambda args: f"({args[0]} - {args[1]})",
   'Distinct': lambda args: f"({args[0]}) != 0",
   'Equal': lambda args: f"({args[0]}) = 0",
   'Extract': lambda args: f"({args[0]})bytes_{args[1]}_{int(args[2]) - 1}" if len(args) == 3 else "Extract-ERR"
}

def extract_arguments(expr):
   """Extract arguments from the operation's parentheses."""
   open_paren = expr.find('(')
   close_paren = expr.rfind(')')
   if open_paren == -1 or close_paren == -1:
       return [], expr  # Invalid expression if no parentheses are found
   
   args_str = expr[open_paren + 1:close_paren].strip()
   args = []
   balance = 0
   current_arg = ''
   
   # Iterate over characters to split arguments while handling nested parentheses
   for char in args_str:
       if char == ',' and balance == 0:
           args.append(current_arg.strip())
           current_arg = ''
       else:
           current_arg += char
           if char == '(':
               balance += 1
           elif char == ')':
               balance -= 1

   if current_arg:
       args.append(current_arg.strip())
   
   return args, expr[:open_paren]  # Return the arguments and the operation before the parentheses

def simplify_expression(expr):
   """Simplify the expression recursively."""
   print(f"Starting to simplify: {expr}")
   
   # Continue simplifying while we can find operations
   while '(' in expr:
       open_paren = expr.find('(')
       close_paren = expr.rfind(')')
       
       # Extract the sub-expression inside the parentheses
       sub_expr = expr[open_paren + 1:close_paren]
       
       # Find the operation before the parentheses
       operation = expr[:open_paren].strip()
       
       print(f"Found operation: {operation} with arguments: {sub_expr}")
       
       # If there's no valid operation, stop processing
       if operation not in operation_rules:
           break
           raise ValueError(f"Unknown operation: {operation}")
       
       # Extract the arguments for this operation
       args, remaining_expr = extract_arguments(expr)
       
       print(f"Extracted arguments: {args}")
       
       # Simplify each argument recursively
       simplified_args = []
       for idx, arg in enumerate(args):
           print(f"Starting to simplify argument {idx + 1}: {arg}")
           simplified_arg = simplify_expression(arg) if '(' in arg else arg
           simplified_args.append(simplified_arg)
           print(f"Updated argument {idx + 1}: {simplified_arg}")
       
       # Simplify the current operation
       simplified_expr = operation_rules[operation](simplified_args)
       
       print(f"Simplified {operation}: {simplified_args} -> {simplified_expr}")
       
       # Replace the whole part with the simplified expression
       #expr = '(' + simplified_expr + ')'  # Replace with just a '(' instead of remaining_expr[:open_paren]
       expr = simplified_expr  # Replace with just a '(' instead of remaining_expr[:open_paren]
       print(f"Updated expression: {expr}")
   
   # If no more operations are left, return the expression as-is
   print(f"No more operations to simplify in: {expr}")
   return expr.strip()

def process_input_file(input_file, output_file):
   """Process the input file and simplify each expression."""
   with open(input_file, 'r') as infile:
       expressions = infile.readlines()

   simplified_expressions = []
   for expr in expressions:
       expr = expr.strip()
       if not expr:
           continue
       
       print(f"Starting to simplify: {expr}")
       simplified = simplify_expression(expr)
       print(f"Final simplified expression: {simplified}")
       simplified_expressions.append(f"{simplified}")

   # Combine the simplified expressions with AND
   final_expression = "\t\t AND \n".join(simplified_expressions)
   
   # Output to the console and write to the output file
   print("\nFinal combined expression:")
   print(final_expression)

   with open(output_file, 'w') as outfile:
       outfile.write(final_expression)

# Main execution
input_file = 'input.expr'
output_file = 'output.expr'
process_input_file(input_file, output_file)