# ZeroAI Agent Client

讓 ZeroAI 在你自己的電腦上做事：跑指令、讀寫檔案、查網頁，做完把結果告訴你。
可以直接在電腦上下任務，也可以在 Discord 用 `/agent run` 遠端交代。限 Pro 以上的個人方案。

## 安裝與綁定

需要 Python 3.10 以上。

```bash
pip install -r requirements.txt
```

1. 在 Discord 輸入 `/agent bind`，拿到配對碼與伺服器網址。
2. 在電腦上執行（10 分鐘內）：

   ```bash
   python zeroai_agent.py pair <配對碼> --server <網址>
   ```

3. 讓主機保持在線，接 Discord 的任務：

   ```bash
   python zeroai_agent.py serve
   ```

不想開著 serve 也可以，直接在電腦上跑：

```bash
python zeroai_agent.py run "把下載資料夾裡的 PDF 依年份分資料夾"
```

## 指令

| 指令 | 說明 |
|---|---|
| `pair <碼> --server <網址> [--name <名稱>]` | 綁定這台電腦 |
| `serve` | 用 WebSocket 連上 ZeroAI 等任務（連出去的連線，不必開任何埠） |
| `run "<任務>" [--model <模型>]` | 在這台電腦上跑一個任務，需要核准的操作在終端機問你 |
| `status` | 額度、計費方式、可用模型 |
| `config show`／`config set <鍵> <值>` | 看／改設定 |
| `unpair` | 解除綁定並刪除本機金鑰 |

## 安全

- **絕對禁止**：刪掉整個根目錄或家目錄、格式化磁碟、fork bomb、讀取 Agent 自己的設定與金鑰……任何設定都擋。
- **要你核准**：刪檔、安裝或移除套件、下載後直接執行、改登錄檔或系統服務、關機、強制推送 git、連到其他主機……
  遠端任務會在 Discord 私訊跳出「允許／拒絕」按鈕，只有你按得了；本機任務在終端機問你。5 分鐘沒回應視為拒絕。
- **工作區**：預設是 `~/ZeroAI-Agent`，裡面可以自由讀寫；工作區以外的讀取、寫入、列資料夾都要核准。
  常用的資料夾可以加進 `allowed_dirs`（多個用 `;` 分隔）。
- **不接受遠端任務**：`config set remote_tasks false`，只能在電腦上自己下任務。
- **金鑰**：存在 `~/.zeroai-agent/config.json`，只能用來呼叫你自己帳號的 Agent，隨時可以在 Discord 用 `/agent unbind` 撤銷。
  工具輸出裡出現金鑰會自動遮掉。模型的 API 金鑰一直在 ZeroAI 那邊，不會到你的電腦。

`config set approval off` 會關掉核准提問（絕對禁止清單照樣擋）。只建議在拋棄式的虛擬機或容器裡這樣做。

## 計費

每一步呼叫模型時，依實際 token 用量換算點數，扣你的五小時／每週額度，用完再扣加購點數：

```
點數 = 模型基準點數 × (輸入 token + 輸出 token × 4) ÷ 10,000
```

模型基準點數就是一般對話每則的點數；0 點的模型在 Agent 裡至少照 0.2 計。Agent 每一步都會把到目前為止的對話送出，
步數越多每一步越大；對話太長時會自動省略較早的工具輸出。模型呼叫失敗不扣點。`status` 會顯示目前的換算方式。

## 記憶與技能

- `~/.zeroai-agent/memory.md`：Agent 用 `memory` 工具記下的長期記憶（偏好、這台電腦的環境），每個任務開始時會帶上。可以直接編輯。
- `~/.zeroai-agent/skills/<名稱>/SKILL.md`：技能說明（與 agentskills.io 相同的資料夾格式，開頭的 `description:` 會列給 Agent 看），
  Agent 需要時用 `read_skill` 讀完整內容照著做。

記憶與技能只存在你的電腦，除非被放進當次對話，否則不會上傳。

## 設計來源

工具呼叫迴圈、危險指令核准與絕對禁止清單、配對碼、可累積的記憶與技能，參考了 Nous Research 的
[Hermes Agent](https://github.com/NousResearch/hermes-agent)（MIT 授權）的設計；程式碼是另外寫的，模型呼叫改走 ZeroAI 並扣 ZeroAI 的額度。

## 授權

本軟體依 [ZeroAI Agent Client 使用授權條款](LICENSE) 提供，另應遵守 [ZeroAI 服務條款](https://zeroai.my/terms/)
與[隱私權政策](https://zeroai.my/privacy/)。重點：

- 只能連 ZeroAI 官方服務，只能用在 ZeroAI Agent 功能；不能把模型呼叫當一般 AI API 用、轉售或拿去做別的產品。
- 只裝在你自己的、或已經取得授權控制的電腦上；電腦上執行的一切操作視為你自己做的，核准前請自己判斷、自己備份。
- 可以為自己使用修改；修改版不能分享。未修改的版本可以免費分享，但要附上 LICENSE。
- 不能用於商業用途。商業授權或其他用途請聯絡 info@anteam.net。

Copyright (c) 2026 一個團隊網路科技工作室 (anTeam Network Studio). All rights reserved.
