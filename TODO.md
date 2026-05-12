# TODO: Feature and Confidence Selection Flow

## Task: After selecting access mode, let user select features and confidence levels before showing data

### Steps to Complete:

- [x] 1. Add new state variables (selectedFeatures, selectedConfidences, isSubmitted)
- [x] 2. Add Feature Selection step (Step 3)
- [x] 3. Add Confidence Selection step (Step 4)  
- [x] 4. Update step indicator to show 4 steps
- [x] 5. Modify submit button to collect events and show results
- [x] 6. Remove/hide graph when showing results
- [x] 7. Send selected features and confidences to backend API

### New Step Flow:
1. Time Slot → 2. Access Mode → 3. Feature Selection → 4. Confidence Selection → 5. Results (no graph)

