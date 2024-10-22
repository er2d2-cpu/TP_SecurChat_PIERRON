TP

Partie 1 :

1) Nous avons la topologie client/serveur avec ici un serveur et 2 clients.
2) Les messages apparaissent dans le terminal du serveur : I
NFO:ChatServer:client1 send message : bonjour
INFO:ChatServer:message send to client2

3) problème de confidentialité
4) La méthode la plus simple est de na pas afficher ces logs, mais le serveur à quand même accès aux messages donc  pour pallier ce problème, il faudrait chiffrer les messages entre le clients pour ne pas que le serveur puissent les analyser. 
Etapes : création du message, chiffrement, envoi, puis déchiffrement par l’autre client (existence d’algorithmes avec des clefs…)

Partie 2 :

1)  La fonction os.urandom() génère des données cryptographiquement sécurisées en utilisant des sources d'entropie du système. Elle produit des valeurs aléatoires difficiles à prédire, essentielles pour le chiffrement, et fonctionne de manière non-bloquante.
2) Utiliser des primitives cryptographiques sans une compréhension approfondie comporte des risques. Une mauvaise utilisation, comme la réutilisation d'un IV, peut exposer des messages. De plus, des failles dans certaines primitives peuvent être exploitées, rendant le système vulnérable.
3) Un serveur malveillant peut causer des problèmes même avec des données chiffrées. Par exemple, lors d'une attaque MITM, l'attaquant peut intercepter et modifier des communications, même chiffrées. Il peut également enregistrer des métadonnées utiles pour des attaques.
4) La confiance dans l'authenticité des entités (client et serveur) est essentielle. Si un serveur malveillant se fait passer pour un serveur légitime, même des communications chiffrées peuvent être compromises. L'intégrité des messages doit également être garantie, par exemple avec des signatures numériques ou des MAC.
Partie3 : 
1) Fernet est moins risqué car il offre une API simple combinant chiffrement et authentification, intégrant un HMAC pour garantir l'intégrité des messages.
2) L'attaque par rejeu (replay attack) permet à un attaquant d'intercepter un message légitime pour le renvoyer ultérieurement.
3) Pour éviter cela, on peut ajouter un nonce ou un timestamp unique à chaque message, permettant de détecter et rejeter les messages déjà envoyés ou expirés.

Partie 4 :

1) L'utilisation de Fernet avec un TTL (Time To Live) ajoute une sécurité en limitant la validité des messages, réduisant le risque d'exploitation des messages interceptés.
2) En soustrayant 45 secondes lors de l'émission, le message sera considéré comme expiré au déchiffrement, entraînant une exception InvalidToken.
3) Cette méthode est efficace contre l'attaque précédente car un message expiré ne peut pas être déchiffré, limitant ainsi les possibilités d'exploitation.
4)Cependant, des limites pratiques existent. Des délais de transmission peuvent amener des messages légitimes à expirer avant d'atteindre leur destination. De plus, une synchronisation précise des horloges entre clients et serveur est cruciale. Un attaquant peut également tenter des attaques par rejeu en envoyant des messages dans des délais plus courts, nécessitant des protections supplémentaires.

Analyse critique:

Utilisation de bibliothèques tierces comme cryptography : bien que reconnues, elles peuvent contenir des vulnérabilités. Si elles ne sont pas mises à jour régulièrement, je pourrais être exposé à des attaques sans le savoir.
Pour générer ma clé de chiffrement, je hache un mot de passe avec SHA256. Cependant, sans salage, un attaquant peut facilement deviner ou cracker un mot de passe faible.
Mes logs d'erreurs pourraient révéler trop d'informations sur les erreurs de déchiffrement, facilitant le travail d'un attaquant.
Enfin, j’ai passé beaucoup de temps sur ce TP, et tout n’est pas encore clair. Je prévois de revoir le code pour bien comprendre chaque ligne lorsque j'aurai du temps.


