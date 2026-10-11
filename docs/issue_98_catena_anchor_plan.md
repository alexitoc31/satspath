# Plan de Implementación — Issue #98
## Catena-Style OP_RETURN Chain for Single-History Property

> **Repositorio**: `satspath/satspath`  
> **Issue**: [#98 — [IMPORTANT] I9: Catena-style OP_RETURN chain for single-history property](https://github.com/satspath/satspath/issues/98)  
> **Entrega**: Pull Request apuntando a `main` en `satspath/satspath`, branch `feat/issue-98-catena-anchor`  
> **Referencias**:
> - `crates/satspath-core/src/transparency/anchor.rs`
> - `docs/key_transparency.md` (§ Regtest anchoring)
> - Paper: *"Catena: Efficient Non-equivocation via Bitcoin"* (Tomescu & Devadas, IEEE S&P 2017)

---

## 1. Contexto y Problema

### Limitación Actual de los Anclajes Independientes
Actualmente, SatsPath implementa el anclaje de checkpoints en Bitcoin mediante [`RegtestAnchorClient`](../crates/satspath-core/src/transparency/anchor.rs) utilizando transacciones `OP_RETURN` individuales:

```text
Tx_A: [Wallet UTXO] ---> [OP_RETURN Commitment_A] + [Change]
Tx_B: [Wallet UTXO] ---> [OP_RETURN Commitment_B] + [Change]
```

En este esquema:
1. **Falta de encadenamiento causal en Bitcoin**: Cada transacción de anclaje gasta UTXOs arbitrarios provistos por la billetera y no está vinculada criptográficamente a la transacción de anclaje anterior.
2. **Vulnerabilidad a Vistas Divididas (Split-View / Equivocation)**: Un operador malicioso o comprometido podría generar dos series paralelas de checkpoints ($A_1, A_2, \dots$ y $B_1, B_2, \dots$) y anclarlas en transacciones separadas de Bitcoin.
3. **Sobrecarga de Auditoría**: Para que un auditor o cliente ligero compruebe que no existen anclajes contradictorios, tendría que escanear y procesar **todos los bloques de Bitcoin**, ya que cualquier transacción en la red podría ser un anclaje alternativo del operador.

### La Solución Catena (Tomescu & Devadas, 2017)
Catena transforma a Bitcoin en un **servicio de consenso de no-equivocación de solo-lectura**:
- El registro se inicia con una **transacción génesis** conocida públicamente ($Tx_0$) que crea un UTXO de continuación $V_0$.
- Cada anclaje posterior $Tx_i$ ($i \ge 1$) **debe gastar obligatoriamente** el UTXO de continuación $V_{i-1}$ de la transacción $Tx_{i-1}$.
- Dado que las reglas de consenso de Bitcoin prohíben estrictamente el doble gasto de cualquier UTXO, **dentro de una historia canónica de Bitcoin para un outpoint génesis fijado, el operador no puede generar dos anclajes válidos a la misma altura sin provocar un doble gasto que los mineros y nodos de Bitcoin rechazarán** (gastos conflictivos no confirmados en mempool y reorganizaciones de cadena permanecen como consideraciones de finalidad resueltas mediante confirmaciones acumuladas).

---

## 2. Arquitectura del Protocolo Catena en SatsPath

```mermaid
flowchart LR
    subgraph Genesis["Genesis Tx0"]
        G_IN["Funding Inputs"] --> G_TX["Tx0"]
        G_TX --> G_OPR["OP_RETURN Commitment 0"]
        G_TX --> V0["Continuation UTXO V0 (1000 sats)"]
    end

    subgraph Anchor1["Anchor Tx1 (Checkpoint 1)"]
        V0 --> A1_TX["Tx1"]
        FEE1["Fee Input"] --> A1_TX
        A1_TX --> A1_OPR["OP_RETURN Commitment 1"]
        A1_TX --> V1["Continuation UTXO V1 (1000 sats)"]
        A1_TX --> CHG1["Change"]
    end

    subgraph Anchor2["Anchor Tx2 (Checkpoint 2)"]
        V1 --> A2_TX["Tx2"]
        FEE2["Fee Input"] --> A2_TX
        A2_TX --> A2_OPR["OP_RETURN Commitment 2"]
        A2_TX --> V2["Continuation UTXO V2 (1000 sats)"]
        A2_TX --> CHG2["Change"]
    end

    classDef utxo fill:#d4edda,stroke:#28a745,stroke-width:2px;
    classDef opreturn fill:#e2e3e5,stroke:#6c757d,stroke-width:2px;
    class V0,V1,V2 utxo;
    class G_OPR,A1_OPR,A2_OPR opreturn;
```

### Invariantes Criptográficas y de Consenso

1. **Génesis Fijo y Anunciado**: El identificador de la cadena Catena está unívocamente determinado por `GenesisOutpoint = (genesis_txid, genesis_vout)`.
2. **Linealidad Estricta**: Para todo $i \ge 1$, el input de continuación de $Tx_i$ debe referenciar exactamente el outpoint `(txid_{i-1}, vout_continuation_{i-1})`.
3. **Compromiso Inmutable**: Cada $Tx_i$ incluye una salida `OP_RETURN` con `6a20<SHA256("SatsPathCatenaAnchorV1" || chain_index_be64 || checkpoint_hash)>` (la etiqueta de dominio forma parte del pre-image del hash SHA-256 de 32 bytes, no viaja en texto plano en la cadena).
4. **Conservación de Capital**: El valor del UTXO de continuación (e.g. 1,000 satoshis) se transfiere de $Tx_{i-1}$ a $Tx_i$, deduciendo únicamente las tarifas de red normales a través de un input de tarifa complementario.

---

## 3. Especificación de Tipos y Estructuras (`satspath-core`)

En `crates/satspath-core/src/transparency/catena.rs` y `anchor.rs`:

```rust
use serde::{Deserialize, Serialize};
use crate::BitcoinNetwork;

/// Parámetros del punto de partida inmutable de la cadena Catena.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatenaGenesis {
    pub network: BitcoinNetwork,
    pub txid: String,
    pub continuation_vout: u32,
    pub commitment: String,
    pub block_hash: Option<String>,
    pub block_height: Option<u64>,
}

/// Registro de un eslabón confirmado en la cadena Catena (extendido sobre BitcoinAnchor con compatibilidad retroactiva).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BitcoinAnchor {
    pub network: BitcoinNetwork,
    pub txid: String,
    pub block_hash: Option<String>,
    pub block_height: Option<u64>,
    pub confirmations: u32,
    pub commitment: String,
    pub verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_txid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_vout: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation_vout: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_index: Option<u64>,
}

/// Prueba de trazabilidad y encadenamiento Catena desde el génesis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatenaChainProof {
    pub genesis: CatenaGenesis,
    pub anchors: Vec<BitcoinAnchor>,
    pub latest_txid: String,
    pub verified: bool,
}

/// Prueba de no-equivocación y detección de bifurcación (split-view).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatenaEquivocationProof {
    pub chain_index: u64,
    pub spent_txid: String,
    pub spent_vout: u32,
    pub first_anchor: BitcoinAnchor,
    pub second_anchor: BitcoinAnchor,
    pub evidence: String,
}
```

> **Nota de implementación y compatibilidad**: Se preservó la compatibilidad con el esquema de almacenamiento de `TransparencyCheckpoint` integrando los campos de encadenamiento Catena opcionales directamente en `BitcoinAnchor` sin requerir migraciones de base de datos disruptivas. Los endpoints expuestos en el daemon son `POST /v1/transparency/anchors`, `GET /v1/transparency/catena/chain`, y `POST /v1/transparency/verify/catena`.

### Formato del Compromiso `OP_RETURN` (V2)

```rust
pub fn catena_commitment(checkpoint_hash: &str, chain_index: u64) -> Result<String, hex::FromHexError> {
    let mut h = sha2::Sha256::new();
    h.update(b"SatsPathCatenaAnchorV1");
    h.update(&chain_index.to_be_bytes());
    h.update(hex::decode(checkpoint_hash)?);
    Ok(hex::encode(h.finalize()))
}
```

---

## 4. Algoritmos de Construcción y Verificación

### 4.1 Construcción del Siguiente Anclaje (`anchor_catena_next` / `anchor_catena_next_with_hook`)

Cuando el daemon emite un nuevo checkpoint en el log de transparencia:
1. **Consulta del Último Estado**: Recupera el último anclaje registrado (`BitcoinAnchor`) en el log de transparencia (o crea el génesis si es el primer anclaje).
2. **Selección del UTXO de Continuación**: Especifica el input 0 como `(prev_txid, continuation_vout)`.
3. **Construcción de Salidas**:
   - Output 0: `OP_RETURN <catena_commitment>`
   - Output 1: `continuation_address` (P2TR o P2WPKH del operador) con valor de 1,000 satoshis.
4. **Financiación y Firma**:
   - Bitcoin Core agrega inputs adicionales para cubrir el fee mediante `fundrawtransaction`.
   - Se firman todos los inputs usando la billetera de Bitcoin Core mediante `signrawtransactionwithwallet` (o desacoplado vía `create_signed_catena_next`).
5. **Transmisión y Confirmación**: Se emite la transacción mediante `broadcast_raw_transaction` / `sendrawtransaction`, se mina un bloque y el anclaje confirmado se almacena dentro de `TransparencyCheckpoint.bitcoin_anchor`.

### 4.2 Verificación de Cadena Hacia Atrás (Backward Verification)

Un verificador o cliente que recibe un `BitcoinAnchor` para un checkpoint realiza:
1. Comprueba que el `OP_RETURN` contiene el compromiso válido del checkpoint.
2. Obtiene la transacción $Tx_i$ desde su nodo Bitcoin o API RPC.
3. Verifica que el input 0 gasta $(Tx_{i-1}, vout_{cont})$.
4. Itera recursivamente hasta alcanzar $(genesis\_txid, genesis\_vout)$.
5. Valida que cada anclaje esté confirmado (`confirmations > 0`; los clientes y auditores imponen la profundidad de confirmaciones requerida según su política de finalidad).

### 4.3 Detección de Equivocación (Split-View Detection)

Si un observador $A$ tiene un anclaje con hash de checkpoint $H_A$ y el observador $B$ tiene $H_B$ para el mismo `chain_index`, o si una transacción alternativa gasta el mismo $(Tx_{i-1}, vout_{cont})$ con diferente compromiso:
- Se genera un `CatenaEquivocationProof` conteniendo ambos registros de anclaje candidatos (`BitcoinAnchor`).
- Este objeto constituye evidencia candidata que los clientes y observadores deben contrastar contra la red Bitcoin para verificar el intento de doble gasto del operador.

---

## 5. Análisis de Costos y Política de Anclaje para Mainnet

### Presupuesto de Bytes y Satoshis
| Parámetro | OP_RETURN Tradicional | Catena Chained Anchor |
|-----------|------------------------|-----------------------|
| **Inputs** | 1 Taproot (~57.5 vB) | 2 Taproot (Continuation + Fee, ~115 vB) |
| **Outputs** | OP_RETURN (43 vB) + Change (43 vB) | OP_RETURN (43 vB) + Cont UTXO (43 vB) + Change (43 vB) |
| **Tamaño Total** | ~110 – 140 vbytes | ~180 – 210 vbytes |
| **Capital Bloqueado** | 0 sats | 1,000 sats (fijo, recirculado perpetuamente) |
| **Costo por Anclaje (a 15 sat/vB)** | ~1,800 sats (~$1.20 USD) | ~3,000 sats (~$2.00 USD) |

### Política de Anclaje Recomendada (Mainnet Budgeting)
1. **Anclaje por Épocas (Periodic Anchoring)**:
   - Anclar 1 vez cada 24 horas (o cada 144 bloques de Bitcoin).
   - Costo mensual estimado: $30 \times 3,000 \text{ sats} = 90,000 \text{ sats}$ (~$60 USD/mes), perfectamente viable para un operador de infraestructura.
2. **Anclaje Inmediato por Eventos Críticos (Event-Driven Anchoring)**:
   - Se fuerza un anclaje inmediato si ocurre una rotación de clave de identidad ([`RotateKey`](../crates/satspath-core/src/transparency/mod.rs)), una revocación de método de pago, o una recuperación de cuenta ([`RecoverKey`](../crates/satspath-core/src/recovery.rs)).
3. **Entorno Regtest / Testnet4**:
   - En regtest, anclar en cada bloque de prueba o checkpoint para validar el pipeline CI continuo.

---

## 6. Fases de Implementación y Tareas

### Fase 1: Núcleo Criptográfico y Tipos (`satspath-core`) [COMPLETADA]
- [x] Crear `crates/satspath-core/src/transparency/catena.rs`:
  - Definición de `CatenaGenesis`, `BitcoinAnchor` con campos Catena opcionales, `CatenaChainProof`, `CATENA_CONTINUATION_VOUT = 1`.
  - Función de compromiso de dominio `catena_commitment(checkpoint_hash, chain_index)`.
  - Validador local de encadenamiento de transacciones `verify_catena_links(...)`.
  - Validador de compromisos `verify_catena_commitments(...)`.
  - Detector de equivocación `detect_catena_equivocation(...)`.
- [x] Exponer el módulo en `crates/satspath-core/src/transparency/mod.rs` y `crates/satspath-core/src/lib.rs`.

### Fase 2: Cliente RPC y Gestor de Cadena Bitcoin Core [COMPLETADA]
- [x] Extender `RegtestAnchorClient` en `crates/satspath-core/src/transparency/anchor.rs`:
  - `anchor_catena_genesis()` / `anchor_catena_genesis_with_hook()`: crea y financia la transacción génesis con vout 1 canonical.
  - `anchor_catena_next()` / `anchor_catena_next_with_hook()`: arma y transmite la transacción con gasto del UTXO de continuación previo y generación del nuevo vout 1.
  - `create_signed_catena_next()` y `broadcast_raw_transaction()`: desacopla firma y transmisión para pruebas de equivocación.
  - `verify_catena_chain()` y `verify_catena_chain_with_checkpoints()`: consulta y verifica la secuencia de transacciones hacia atrás hasta el génesis.

### Fase 3: Persistencia Transaccional en SQLite (`satspathd`) [SUPERADA POR DISEÑO COMPATIBLE]
- [x] En lugar de una migración de esquema SQLite disruptiva (v11), se integraron los campos Catena opcionales (`prev_txid`, `prev_vout`, `continuation_vout`, `chain_index`) directamente en `BitcoinAnchor`, persistidos dentro del JSON de `TransparencyCheckpoint` existente y respaldados en la tabla `anchors`.
- [x] Persistencia atómica de anclajes pendientes (`catena_pending_anchor.json`) para reconciliación post-reinicio antes de transmisión.
- [x] Integración de `replace_checkpoint_by_hash` y `replace_latest_checkpoint` con validación de compromisos y prevención de sobreescritura.

### Fase 4: Endpoints del Daemon y Verificación [COMPLETADA / ADAPTADA]
- [x] Endpoint `GET /v1/transparency/catena/chain`: expone la secuencia completa de anclajes Catena registrados en el log.
- [x] Endpoint `POST /v1/transparency/verify/catena`: valida consistencia estructural y compromisos criptográficos en memoria.
- [x] Endpoint `POST /v1/transparency/anchors`: ancla el checkpoint más reciente encadenando al último anclaje Catena existente.

### Fase 5: Pruebas Automatizadas y Validación [COMPLETADA]
- [x] Pruebas unitarias en `catena.rs` y `log.rs` simulando secuencias válidas, rechazo de índices/vouts no canónicos y compromisos.
- [x] Pruebas de integración en `crates/satspath-core/tests/regtest_anchor.rs`:
  - Creación de génesis.
  - Creación secuencial de anclajes encadenados.
  - Verificación hacia atrás con Bitcoin Core RPC y binding de checkpoints.
  - Prueba de doble gasto pre-firmando dos ramas y verificando el rechazo nativo de Bitcoin Core (`bad-txns-inputs-missingorspent`).
- [x] Pruebas de endpoints HTTP en `satspathd` (`test_catena_endpoints`).
- [x] Actualización de documentación y diagramas Mermaid en `docs/key_transparency.md`.

---

## 7. Criterios de Aceptación (Definition of Done)
1. **Unicidad y Resistencia a Bifurcación**: La prueba de integración demuestra que no es posible generar dos anclajes aceptados por Bitcoin Core para el mismo eslabón de la cadena sin que Bitcoin rechace el segundo por intento de doble gasto. La verificación vincula explícitamente el outpoint génesis fijado (`genesis_txid:genesis_vout`).
2. **Compatibilidad Descendente**: Si no se configura `SATSPATH_BITCOIN_NETWORK=regtest`, el daemon continúa operando normalmente en modo local o witness-only sin fallos, persistiendo los anclajes opcionales dentro de `TransparencyCheckpoint.bitcoin_anchor`.
3. **Auditoría de Cadena**: Un cliente externo o auditor puede verificar la cadena completa de anclajes Catena hacia atrás hasta el génesis mediante `RegtestAnchorClient::verify_catena_chain(latest_txid, genesis_txid, genesis_vout)`, validar la consistencia estructural mediante `/v1/transparency/verify/catena` o inspeccionar el historial con `/v1/transparency/catena/chain` y `/v1/transparency/anchors`.
4. **CI en Verde**: Todos los tests de workspace, linter clippy, formateo y análisis de CodeRabbit pasan sin advertencias.
