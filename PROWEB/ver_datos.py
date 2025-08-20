import sqlite3

def ver_datos():
    conn = sqlite3.connect('usuarios.db')
    c = conn.cursor()
    
    print("Usuarios registrados:")
    c.execute("SELECT * FROM usuarios")
    usuarios = c.fetchall()
    for usuario in usuarios:
        print(usuario)
    
    print("\nMensajes de contacto:")
    c.execute("SELECT * FROM contacto")
    contactos = c.fetchall()
    for contacto in contactos:
        print(contacto)
    
    conn.close()

if __name__ == '__main__':
    ver_datos()
