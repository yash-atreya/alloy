#[cfg(not(feature = "kzg"))]
use alloy_eips::eip4844::Blob;
#[cfg(feature = "kzg")]
use c_kzg::{Blob, KzgCommitment, KzgProof, KzgSettings};

use std::marker::PhantomData;

use alloy_eips::eip4844::{BYTES_PER_BLOB, FIELD_ELEMENTS_PER_BLOB};

use super::utils::WholeFe;

/// A builder for creating a [`BlobTransactionSidecar`].
///
/// [`BlobTransactionSidecar`]: crate::BlobTransactionSidecar
#[derive(Debug, Clone)]
pub struct PartialSidecar {
    /// The blobs in the sidecar.
    blobs: Vec<Blob>,
    /// The number of field elements that we have ingested, total.
    fe: usize,
}

impl Default for PartialSidecar {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialSidecar {
    /// Create a new builder.
    pub fn new() -> Self {
        // NB: vecs default to 100 capacity. Blobs are large. We don't want
        // to allocate 100 blobs if we don't need them.
        Self::with_capacity(2)
    }

    /// Create a new builder with a given capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let mut blobs = Vec::with_capacity(capacity);
        blobs.push(Blob::new([0u8; BYTES_PER_BLOB]));
        Self { blobs, fe: 0 }
    }

    /// Get a reference to the blobs currently in the builder.
    pub fn blobs(&self) -> &[Blob] {
        &self.blobs
    }

    /// Get the number of unused field elements that have been allocated
    fn free_fe(&self) -> usize {
        self.blobs.len() * FIELD_ELEMENTS_PER_BLOB as usize - self.fe
    }

    /// Calculate the length of used field elements IN BYTES in the builder.
    ///
    /// This is always strictly greater than the number of bytes that have been
    /// ingested.
    pub const fn len(&self) -> usize {
        self.fe * 32
    }

    /// Check if the builder is empty.
    pub const fn is_empty(&self) -> bool {
        self.fe == 0
    }

    /// Push an empty blob to the builder, and reset the unused counter.
    fn push_empty_blob(&mut self) {
        self.blobs.push(Blob::new([0u8; BYTES_PER_BLOB]));
    }

    /// Allocate enough space for the required number of new field elements.
    pub fn alloc_fes(&mut self, required_fe: usize) {
        while self.free_fe() < required_fe {
            self.push_empty_blob()
        }
    }

    /// Get the number of used field elements in the current blob.
    const fn fe_in_current_blob(&self) -> usize {
        self.fe % FIELD_ELEMENTS_PER_BLOB as usize
    }

    /// Get the index of the first unused field element in the current blob.
    const fn first_unused_fe_index_in_current_blob(&self) -> Option<usize> {
        if self.fe_in_current_blob() as u64 == FIELD_ELEMENTS_PER_BLOB {
            None
        } else {
            Some(self.fe_in_current_blob())
        }
    }

    /// Get a mutable reference to the current blob.
    fn current_blob_mut(&mut self) -> &mut Blob {
        self.blobs.last_mut().expect("never empty")
    }

    /// Get a mutable reference to the field element at the given index, in
    /// the current blob.
    fn fe_at_mut(&mut self, index: usize) -> &mut [u8] {
        &mut self.current_blob_mut()[index * 32..(index + 1) * 32]
    }

    /// Get a mutable reference to the next unused field element.
    fn next_unused_fe_mut(&mut self) -> &mut [u8] {
        if self.first_unused_fe_index_in_current_blob().is_none() {
            self.push_empty_blob();
        }
        self.fe_at_mut(self.first_unused_fe_index_in_current_blob().expect(""))
    }

    /// Ingest a field element into the current blobs.
    ///
    /// # Panics
    ///
    /// If there are not enough free FEs to encode the data.
    pub fn ingest_valid_fe(&mut self, data: WholeFe<'_>) {
        self.next_unused_fe_mut().copy_from_slice(data.as_ref());
        self.fe += 1;
    }

    /// Ingest a partial FE into the current blobs.
    ///
    /// # Panics
    ///
    /// If the data is >=32 bytes. Or if there are not enough free FEs to
    /// encode the data.
    pub fn ingest_partial_fe(&mut self, data: &[u8]) {
        let fe = self.next_unused_fe_mut();
        fe[1..1 + data.len()].copy_from_slice(data);
        self.fe += 1;
    }
}

/// A strategy for coding and decoding data into sidecars.
pub trait SidecarCoder {
    /// Calculate the number of field elements required to store the given
    /// data.
    fn required_fe(data: &[u8]) -> usize;

    /// Code a slice of data into the builder.
    fn code(builder: &mut PartialSidecar, data: &[u8]);

    /// Decode all slices of data from the blobs.
    fn decode_all(blobs: &[Blob]) -> Option<Vec<Vec<u8>>>;
}

/// Simple coder that only uses the last 31 bytes of each blob
#[derive(Debug, Copy, Clone, Default)]
pub struct SimpleCoder;

impl SimpleCoder {
    /// Decode an some bytes from an iterator of valid FEs.
    ///
    /// Returns `Ok(Some(data))` if there is some data.
    /// Returns `Ok(None)` if there is no data (length prefix is 0).
    /// Returns `Err(())` if there is an error.
    fn decode_one<'a>(mut fes: impl Iterator<Item = WholeFe<'a>>) -> Result<Option<Vec<u8>>, ()> {
        let first = fes.next().ok_or(())?;
        let mut num_bytes = u64::from_be_bytes(first.as_ref()[1..9].try_into().unwrap()) as usize;

        // if no more bytes is 0, we're done
        if num_bytes == 0 {
            return Ok(None);
        }

        let mut res = Vec::with_capacity(num_bytes);
        while num_bytes > 0 {
            let to_copy = std::cmp::min(31, num_bytes);
            let fe = fes.next().ok_or(())?;
            res.extend_from_slice(&fe.as_ref()[1..1 + to_copy]);
            num_bytes -= to_copy;
        }
        Ok(Some(res))
    }
}

impl SidecarCoder for SimpleCoder {
    fn required_fe(data: &[u8]) -> usize {
        data.len().div_ceil(31) + 1
    }

    fn code(builder: &mut PartialSidecar, mut data: &[u8]) {
        if data.is_empty() {
            return;
        }

        // first FE is the number of following bytes
        builder.ingest_partial_fe(&(data.len() as u64).to_be_bytes());

        // ingest the rest of the data
        while !data.is_empty() {
            let (left, right) = data.split_at(std::cmp::min(31, data.len()));
            builder.ingest_partial_fe(left);
            data = right
        }
    }

    fn decode_all(blobs: &[Blob]) -> Option<Vec<Vec<u8>>> {
        let mut fes =
            blobs.iter().flat_map(|blob| blob.chunks(32).map(WholeFe::new)).map(Option::unwrap);

        let mut res = Vec::new();
        loop {
            match Self::decode_one(&mut fes) {
                Ok(Some(data)) => res.push(data),
                Ok(None) => break,
                Err(()) => return None,
            }
        }
        Some(res)
    }
}

/// Build a [`BlobTransactionSidecar`] from an arbitrary amount of data.
///
/// This is useful for creating a sidecar from a large amount of data,
/// which is then split into blobs. It delays KZG commitments and proofs
/// until all data is ready.
///
/// [`BlobTransactionSidecar`]: crate::BlobTransactionSidecar
#[derive(Debug, Clone)]
pub struct SidecarBuilder<T = SimpleCoder> {
    inner: PartialSidecar,
    /// The strategy to use for ingesting and decoding data.
    strategy: PhantomData<fn() -> T>,
}

impl<T> Default for SidecarBuilder<T>
where
    T: Default + SidecarCoder,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T: SidecarCoder> SidecarBuilder<T> {
    /// Instantiate a new builder.
    pub fn new() -> Self {
        let mut this = Self { inner: PartialSidecar::default(), strategy: PhantomData };
        this.inner.push_empty_blob();
        this
    }

    /// Calculate the length of bytes used by field elements in the builder.
    ///
    /// This is always strictly greater than the number of bytes that have been
    /// ingested.
    pub const fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the builder is empty.
    pub const fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Create a new builder from a slice of data.
    pub fn from_slice(data: &[u8]) -> SidecarBuilder<T> {
        let mut this = Self::new();
        this.ingest(data);
        this
    }

    /// Ingest a slice of data into the builder.
    pub fn ingest(&mut self, data: &[u8]) {
        self.inner.alloc_fes(T::required_fe(data));
        T::code(&mut self.inner, data);
    }

    #[cfg(feature = "kzg")]
    /// Build the sidecar from the data.
    pub fn build(
        self,
        settings: &KzgSettings,
    ) -> Result<crate::BlobTransactionSidecar, c_kzg::Error> {
        let commitments = self
            .inner
            .blobs
            .iter()
            .map(|blob| KzgCommitment::blob_to_kzg_commitment(blob, settings).map(|c| c.to_bytes()))
            .collect::<Result<Vec<_>, _>>()?;

        let proofs = self
            .inner
            .blobs
            .iter()
            .zip(commitments.iter())
            .map(|(blob, commitment)| {
                KzgProof::compute_blob_kzg_proof(blob, commitment, settings).map(|p| p.to_bytes())
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(crate::BlobTransactionSidecar { blobs: self.inner.blobs, commitments, proofs })
    }

    /// Take the blobs from the builder, without committing them to a KZG proof.
    pub fn take(self) -> Vec<Blob> {
        self.inner.blobs
    }
}

impl<T, R> FromIterator<R> for SidecarBuilder<T>
where
    T: SidecarCoder,
    R: AsRef<[u8]>,
{
    fn from_iter<I: IntoIterator<Item = R>>(iter: I) -> Self {
        let mut this = Self::new();
        for data in iter {
            this.ingest(data.as_ref());
        }
        this
    }
}

#[cfg(test)]
mod tests {
    use alloy_eips::eip4844::USABLE_BYTES_PER_BLOB;

    use super::*;

    #[test]
    fn ingestion_strategy() {
        let mut builder = PartialSidecar::new();
        let data = &[vec![1u8; 32], vec![2u8; 372], vec![3u8; 17], vec![4u8; 5]];

        data.iter().for_each(|data| SimpleCoder::code(&mut builder, data.as_slice()));

        let decoded = SimpleCoder::decode_all(builder.blobs()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn it_ingests() {
        // test ingesting a lot of data.
        let data = [
            vec![1u8; 32],
            vec![2u8; 372],
            vec![3u8; 17],
            vec![4u8; 5],
            vec![5u8; USABLE_BYTES_PER_BLOB + 2],
        ];

        let mut builder = data.iter().collect::<SidecarBuilder<SimpleCoder>>();

        let expected_fe = data.iter().map(|d| SimpleCoder::required_fe(d)).sum::<usize>();
        assert_eq!(builder.len(), expected_fe * 32);

        // consume 2 more
        builder.ingest("hello".as_bytes());
        assert_eq!(builder.len(), expected_fe * 32 + 64);
    }
}
