#pragma once


class ETWVarlenReader {
public:
	/*
	* structlen should be length of struct without variable-length fields
	*/
	ETWVarlenReader(char *pstruct, size_t structlen, size_t datalen) :
		pstruct_(pstruct), structlen_(structlen), datalen_(datalen),
		currentOffset_(structlen) {}

	/*
	* return true on error, false on success
	*/
	bool readSID(PSID &pdest) {
		if (pstruct_ == nullptr || ((currentOffset_ + 8) >= datalen_)) {
			return true;
		}
		uint32_t *pvarsid = (uint32_t*)(pstruct_ + currentOffset_);
		currentOffset_ += sizeof(uint32_t);
		if (*pvarsid != 0) {

			// skip over TOKEN_USER struct
			currentOffset_ += 8; // sizeof(TOKEN_USER);
			if ((currentOffset_ + 8) >= datalen_) {
				return true;
			}

			// read length of sid

			SID *ptmpsid = (SID *)(pstruct_ + currentOffset_);
			size_t sidlen = 8 + (4 * ptmpsid->SubAuthorityCount);

			if (!IsValidSid(ptmpsid)) { //ptmpsid->Revision != 1) {
				// invalid SID
				currentOffset_ = datalen_; // move to end . fail
				return true;
			}

			// sanity check

			if (sidlen < 8) {
				currentOffset_ = datalen_; // move to end . fail
				return true;
			}

			// assign SID pointer
			pdest = ptmpsid;

			currentOffset_ += sidlen;
		}
		return false;
	}

	/*
	* read or skip varlen string at current offset.
	* @returns true on error, false on success
	*/
	bool readString(std::string *dest = nullptr) {
		return _ReadVarlenStringPrivate<std::string>(dest);
	}

	/*
	* read or skip varlen wide string at current offset
	* @returns true on error, false on success
	*/
	bool readWString(std::wstring *dest = nullptr) {
		return _ReadVarlenStringPrivate<std::wstring>(dest);
	}

	/*
	* Adds delta to currentOffset
	*/
	void addOffset(size_t delta) {
		currentOffset_ += delta;
	}

	/*
	* read or skip varlen string at current offset.
	* @returns true on error, false on success
	*/
	template <class T>
	bool _ReadVarlenStringPrivate(T *dest = nullptr) {

		if ((currentOffset_ + 1 + sizeof(T::value_type)) >= datalen_) {
			return true;
		}
		auto p = (T::value_type *)(pstruct_ + currentOffset_);

		// quick check for empty string

		if (*p == 0) {
			if (dest != nullptr) {
				*dest = T();
			}
			currentOffset_ += sizeof(T::value_type);
			return true;
		}

		T::value_type *end = (T::value_type*)(pstruct_ + datalen_);
		T::value_type *pstart = p;
		while (p < end && *p != (T::value_type)0) { p++; }
		if (p == end) {
			// reached end before null byte
			currentOffset_ = datalen_;
			return true;
		}
		currentOffset_ += (p - pstart + 1);
		if (dest != nullptr) {
			*dest = T(pstart, p - pstart);
		}
		return false;
	}
private:
	char *   pstruct_;
	size_t   structlen_;
	size_t   datalen_;
	size_t   currentOffset_;
};

